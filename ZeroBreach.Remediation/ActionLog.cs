using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroBreach.Remediation;

/// <summary>
/// Append-only, tamper-evident remediation log (spec §6.10). Each JSONL entry's hash covers
/// the previous entry's hash, forming a chain: editing or removing any past entry breaks
/// verification of everything after it.
///
/// A hash chain alone cannot detect TRUNCATION — lopping entries off the end leaves a
/// shorter, perfectly valid chain, which would let an operator (or an attacker with the
/// operator's rights) erase the record of what was destroyed. So each append also writes an
/// anchor beside the log recording the chain's length and head hash, and verification fails
/// when the log is shorter than the anchor. The anchor is not a secret and can itself be
/// deleted; the point is that the record can no longer be quietly shortened by editing ONE
/// file, and a missing or stale anchor is reported as "cannot prove intact" rather than OK
/// (spec §6.7 — never report clean for something that could not be checked).
/// </summary>
public sealed class ActionLog
{
    private readonly string _path;
    private readonly string _anchorPath;

    public ActionLog(string? path = null)
    {
        _path = path ?? ZbPaths.ActionLogPath;
        _anchorPath = _path + ".anchor";
    }

    /// <summary>Outcome of a chain verification.</summary>
    public enum ChainState
    {
        /// <summary>Every link verifies and the anchor agrees with the log.</summary>
        Intact,
        /// <summary>An entry was edited or removed from the middle of the chain.</summary>
        Broken,
        /// <summary>The chain is internally consistent but shorter than the anchor records.</summary>
        Truncated,
        /// <summary>The chain is internally consistent, but the anchor is missing, unreadable
        /// or behind the log, so truncation cannot be ruled out.</summary>
        Unverifiable,
    }

    public sealed record VerifyResult(ChainState State, long BrokenSeq, string? Why, int Entries)
    {
        public bool Ok => State == ChainState.Intact;
    }

    private sealed class Anchor
    {
        [JsonPropertyName("entries")] public int Entries { get; set; }
        [JsonPropertyName("last_seq")] public long LastSeq { get; set; }
        [JsonPropertyName("last_hash")] public string LastHash { get; set; } = GenesisHash;
    }

    public sealed class Entry
    {
        [JsonPropertyName("seq")] public long Seq { get; set; }
        [JsonPropertyName("utc")] public DateTime Utc { get; set; }
        [JsonPropertyName("action")] public required string Action { get; set; }
        [JsonPropertyName("target")] public required string Target { get; set; }
        [JsonPropertyName("finding_id")] public string? FindingId { get; set; }
        [JsonPropertyName("result")] public required string Result { get; set; }
        [JsonPropertyName("detail")] public string? Detail { get; set; }
        [JsonPropertyName("operator")] public string? Operator { get; set; }
        [JsonPropertyName("prev_hash")] public string PrevHash { get; set; } = GenesisHash;
        [JsonPropertyName("hash")] public string Hash { get; set; } = "";
    }

    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>Appends one entry, chaining it to the current tail. Exclusive file lock for
    /// the read-tail + append so two processes can't fork the chain.</summary>
    public Entry Append(string action, string target, string result, string? detail = null, string? findingId = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        using var fs = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        var (lastSeq, lastHash, count) = ReadTail(fs);
        var entry = new Entry
        {
            Seq = lastSeq + 1,
            Utc = DateTime.UtcNow,
            Action = action,
            Target = target,
            FindingId = findingId,
            Result = result,
            Detail = detail,
            Operator = Environment.UserDomainName + "\\" + Environment.UserName,
            PrevHash = lastHash,
        };
        entry.Hash = ComputeHash(entry);

        fs.Seek(0, SeekOrigin.End);
        var line = JsonSerializer.Serialize(entry) + "\n";
        fs.Write(Encoding.UTF8.GetBytes(line));
        fs.Flush(flushToDisk: true);

        WriteAnchor(new Anchor { Entries = count + 1, LastSeq = entry.Seq, LastHash = entry.Hash });
        return entry;
    }

    /// <summary>Anchor write: temp file then atomic replace, so a crash mid-write leaves either
    /// the old anchor or the new one, never a half-written file. Failure to write it is not
    /// allowed to fail the append — the action already happened and the entry is on disk; the
    /// stale anchor then makes verification report Unverifiable, which is the honest state.</summary>
    private void WriteAnchor(Anchor anchor)
    {
        try
        {
            var tmp = _anchorPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(anchor));
            File.Move(tmp, _anchorPath, overwrite: true);
        }
        catch
        {
            // Intentionally swallowed — see the remark above.
        }
    }

    private Anchor? ReadAnchor()
    {
        try
        {
            return File.Exists(_anchorPath)
                ? JsonSerializer.Deserialize<Anchor>(File.ReadAllText(_anchorPath))
                : null;
        }
        catch { return null; }
    }

    /// <summary>Re-walks the whole chain. Returns true only when every link verifies AND the
    /// anchor confirms nothing was cut off the end.</summary>
    public bool Verify(out long brokenSeq, out string? why)
    {
        var result = VerifyChain();
        brokenSeq = result.BrokenSeq;
        why = result.Why;
        return result.Ok;
    }

    /// <summary>Full verification: link-by-link hash chain, then the anchor cross-check that
    /// catches truncation (a hash chain with its tail removed still verifies link-by-link).</summary>
    public VerifyResult VerifyChain()
    {
        var anchor = ReadAnchor();

        if (!File.Exists(_path))
        {
            // No log at all is a valid empty chain — unless an anchor says entries existed.
            if (anchor is { Entries: > 0 })
                return new VerifyResult(ChainState.Truncated, anchor.LastSeq,
                    $"the action log is MISSING but its anchor records {anchor.Entries} entr" +
                    $"{(anchor.Entries == 1 ? "y" : "ies")} through seq {anchor.LastSeq} — the log was deleted",
                    0);
            return new VerifyResult(ChainState.Intact, -1, null, 0);
        }

        var prev = GenesisHash;
        long lastSeq = 0;
        var count = 0;

        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            Entry? e;
            try { e = JsonSerializer.Deserialize<Entry>(line); }
            catch (Exception ex)
            {
                return new VerifyResult(ChainState.Broken, -1, $"unparseable line: {ex.Message}", count);
            }
            if (e is null) continue;

            if (!string.Equals(e.PrevHash, prev, StringComparison.OrdinalIgnoreCase))
                return new VerifyResult(ChainState.Broken, e.Seq,
                    "prev_hash does not match preceding entry", count);

            if (!string.Equals(e.Hash, ComputeHash(e), StringComparison.OrdinalIgnoreCase))
                return new VerifyResult(ChainState.Broken, e.Seq,
                    "entry content does not match its hash", count);

            prev = e.Hash;
            lastSeq = e.Seq;
            count++;
        }

        if (anchor is null)
            return new VerifyResult(ChainState.Unverifiable, -1,
                count == 0
                    ? "no anchor file beside the log; an empty log cannot be distinguished from a deleted one"
                    : "no anchor file beside the log — the chain links verify, but entries removed from " +
                      "the END of the log cannot be detected without it",
                count);

        if (count < anchor.Entries || lastSeq < anchor.LastSeq)
            return new VerifyResult(ChainState.Truncated, anchor.LastSeq,
                $"log TRUNCATED: the anchor records {anchor.Entries} entries through seq {anchor.LastSeq}, " +
                $"but the log holds {count} through seq {lastSeq} — entries were removed from the end",
                count);

        if (count > anchor.Entries || !string.Equals(prev, anchor.LastHash, StringComparison.OrdinalIgnoreCase))
            return new VerifyResult(ChainState.Unverifiable, -1,
                $"anchor is stale (records {anchor.Entries} entries through seq {anchor.LastSeq}); the chain " +
                "links verify, but it cannot confirm the end of the log is complete",
                count);

        return new VerifyResult(ChainState.Intact, -1, null, count);
    }

    public IReadOnlyList<Entry> ReadAll()
    {
        if (!File.Exists(_path)) return Array.Empty<Entry>();
        var list = new List<Entry>();
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { if (JsonSerializer.Deserialize<Entry>(line) is { } e) list.Add(e); }
            catch { /* verify() reports corruption; reading stays best-effort */ }
        }
        return list;
    }

    private static (long seq, string hash, int count) ReadTail(FileStream fs)
    {
        fs.Seek(0, SeekOrigin.Begin);
        long seq = 0; var hash = GenesisHash; var count = 0;
        using var reader = new StreamReader(fs, Encoding.UTF8, leaveOpen: true);
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                if (JsonSerializer.Deserialize<Entry>(line) is { } e) { seq = e.Seq; hash = e.Hash; count++; }
            }
            catch { /* keep last good tail; corrupt tail shows up in Verify */ }
        }
        return (seq, hash, count);
    }

    /// <summary>Canonical content hash: every field except <c>hash</c> itself, in fixed order.</summary>
    private static string ComputeHash(Entry e)
    {
        var canonical = string.Join('\u001f',
            e.Seq, e.Utc.ToString("O"), e.Action, e.Target, e.FindingId ?? "",
            e.Result, e.Detail ?? "", e.Operator ?? "", e.PrevHash);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
