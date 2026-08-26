using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;

namespace ZeroBreach.Formats.Containers;

/// <summary>
/// ZIP central-directory reader (BLUEPRINT §7). The container structures — end-of-central-
/// directory record, central directory, local headers — are parsed here by hand; the BCL is
/// used only for the raw deflate bitstream. Nothing is ever written to disk.
///
/// Trust model: the central directory and the local headers are two independent, possibly
/// lying descriptions of the same bytes. Both are reported; disagreements are surfaced
/// per-field and never merged, because malformed archives disagree deliberately to show one
/// payload to a scanner and another to an extractor.
/// </summary>
public static class ZipReader
{
    private const uint EocdSignature = 0x06054B50;
    private const uint CentralEntrySignature = 0x02014B50;
    private const uint LocalHeaderSignature = 0x04034B50;
    private const uint Zip64LocatorSignature = 0x07064B50;

    private const int EocdFixedSize = 22;
    private const int CentralEntryFixedSize = 46;
    private const int LocalHeaderFixedSize = 30;

    private const ushort FlagEncrypted = 0x0001;
    private const ushort FlagDataDescriptor = 0x0008;
    private const ushort FlagUtf8Name = 0x0800;

    internal const ushort MethodStored = 0;
    internal const ushort MethodDeflate = 8;
    private const ushort MethodAes = 99;

    /// <summary>
    /// CP437 code points for bytes 0x80–0xFF. ZIP names without flag bit 11 are CP437 by
    /// spec; decoding them as Latin-1 or UTF-8 silently renames entries, which matters when
    /// a name is itself the indicator.
    /// </summary>
    private const string Cp437High =
        "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»" +
        "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀" +
        "αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

    /// <summary>Enumerates the central directory. Reads no entry content.</summary>
    public static ZipReadResult Read(byte[] data, ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(budget);

        if (data.LongLength > budget.MaxInputBytes)
        {
            return ZipReadResult.IncompleteWithoutArchive(
                $"input is {data.LongLength} bytes, over the {budget.MaxInputBytes}-byte budget; refused");
        }

        var clock = Stopwatch.StartNew();
        if (clock.Elapsed >= budget.Deadline)
        {
            return ZipReadResult.IncompleteWithoutArchive("deadline exhausted before reading began");
        }

        // --- End-of-central-directory record: scan backwards, strictly anchored.
        // A candidate only counts when its declared comment length lands exactly on the end
        // of the buffer; otherwise random PK\x05\x06 bytes inside data would be accepted.
        if (data.Length < EocdFixedSize)
        {
            return ZipReadResult.Fail(
                $"{data.Length} bytes is smaller than the 22-byte end-of-central-directory record; not a ZIP",
                0);
        }

        long eocd = -1;
        long searchFloor = Math.Max(0, data.Length - ContainerLimits.MaxEocdSearchBytes);
        for (long i = data.Length - EocdFixedSize; i >= searchFloor; i--)
        {
            if (U32(data, i) != EocdSignature)
            {
                continue;
            }
            int commentLen = U16(data, i + 20);
            if (i + EocdFixedSize + commentLen == data.Length)
            {
                eocd = i;
                break;
            }
        }
        if (eocd < 0)
        {
            return ZipReadResult.Fail(
                "no end-of-central-directory record found in the final 65557 bytes; not a ZIP or the tail is truncated",
                null);
        }

        int diskNumber = U16(data, eocd + 4);
        int cdStartDisk = U16(data, eocd + 6);
        int entriesThisDisk = U16(data, eocd + 8);
        int entriesTotal = U16(data, eocd + 10);
        uint cdSize = U32(data, eocd + 12);
        uint cdOffset = U32(data, eocd + 16);

        // ZIP64 uses 0xFFFF / 0xFFFFFFFF sentinels plus a locator record before the EOCD.
        // Treating a sentinel as a real count would misparse, so the variant is reported as
        // unsupported rather than guessed at (fail closed).
        bool zip64Locator = eocd >= 20 && U32(data, eocd - 20) == Zip64LocatorSignature;
        if (zip64Locator || entriesTotal == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF)
        {
            return ZipReadResult.IncompleteWithoutArchive("ZIP64 archive; not supported by this reader");
        }
        if (diskNumber != 0 || cdStartDisk != 0)
        {
            return ZipReadResult.IncompleteWithoutArchive(
                $"multi-disk archive (disk {diskNumber}, directory starts on disk {cdStartDisk}); not supported");
        }
        if (entriesThisDisk != entriesTotal)
        {
            return ZipReadResult.Fail(
                $"end-of-central-directory record lies: {entriesThisDisk} entries on this disk vs {entriesTotal} total on a single-disk archive",
                eocd + 8);
        }

        // The central directory must sit entirely before its own EOCD record. Anything else
        // is a truncated file or lying offsets; either way the directory cannot be trusted.
        if ((long)cdOffset + cdSize > eocd)
        {
            return ZipReadResult.IncompleteWithoutArchive(
                $"central directory [{cdOffset}..{(long)cdOffset + cdSize}) extends past its end-of-central-directory record at {eocd}; archive truncated or offsets lie");
        }

        var reasons = new List<string>();
        int entryCap = Math.Min(ContainerLimits.MaxZipEntries, budget.MaxMatches);
        int entriesToParse = entriesTotal;
        if (entriesTotal > entryCap)
        {
            entriesToParse = entryCap;
            reasons.Add($"archive declares {entriesTotal} entries, over the cap of {entryCap}; only the first {entryCap} enumerated");
        }

        // --- Central directory walk.
        var entries = new List<ZipEntryInfo>(Math.Min(entriesToParse, 1024));
        long pos = cdOffset;
        long cdEnd = (long)cdOffset + cdSize;
        for (int index = 0; index < entriesToParse; index++)
        {
            if (clock.Elapsed >= budget.Deadline)
            {
                reasons.Add($"deadline exhausted after {index} of {entriesTotal} entries");
                break;
            }
            if (pos + CentralEntryFixedSize > cdEnd)
            {
                return ZipReadResult.Fail(
                    $"central directory entry {index} at offset {pos} runs past the directory end at {cdEnd}",
                    pos);
            }
            if (U32(data, pos) != CentralEntrySignature)
            {
                return ZipReadResult.Fail(
                    $"central directory entry {index} at offset {pos}: bad signature 0x{U32(data, pos):X8}",
                    pos);
            }

            ushort flags = (ushort)U16(data, pos + 8);
            ushort method = (ushort)U16(data, pos + 10);
            int dosTime = U16(data, pos + 12);
            int dosDate = U16(data, pos + 14);
            uint crc = U32(data, pos + 16);
            uint compSize = U32(data, pos + 20);
            uint uncompSize = U32(data, pos + 24);
            int nameLen = U16(data, pos + 28);
            int extraLen = U16(data, pos + 30);
            int commentLen = U16(data, pos + 32);
            uint localOffset = U32(data, pos + 42);

            long varEnd = pos + CentralEntryFixedSize + nameLen + extraLen + commentLen;
            if (varEnd > cdEnd)
            {
                return ZipReadResult.Fail(
                    $"central directory entry {index}: name/extra/comment ({nameLen}+{extraLen}+{commentLen} bytes) run past the directory end at {cdEnd}",
                    pos + 28);
            }

            var anomalies = new List<string>();
            bool nameIsUtf8 = (flags & FlagUtf8Name) != 0;
            string name = DecodeName(data.AsSpan((int)(pos + CentralEntryFixedSize), nameLen), nameIsUtf8, anomalies);
            var pathAnomalies = ClassifyPath(name);

            DateTime? lastModified = DecodeDosDateTime(dosDate, dosTime);
            if (lastModified is null)
            {
                anomalies.Add($"DOS timestamp 0x{dosDate:X4}:0x{dosTime:X4} does not encode a valid date-time");
            }

            // A declared ratio past the cap is worth flagging at enumeration time, before
            // anyone decompresses anything — but the authoritative guard runs on actual
            // output in ReadEntry, because declared sizes lie.
            if (uncompSize > ContainerLimits.RatioGuardFloorBytes &&
                uncompSize > ContainerLimits.MaxCompressionRatio * Math.Max(compSize, 1u))
            {
                anomalies.Add(
                    $"declared expansion {compSize} -> {uncompSize} bytes exceeds the {ContainerLimits.MaxCompressionRatio}:1 ratio cap");
            }

            bool encrypted = (flags & FlagEncrypted) != 0 || method == MethodAes;

            var mismatches = new List<string>();
            ZipLocalHeaderInfo? local = ReadLocalHeader(
                data, localOffset, name, flags, method, crc, compSize, uncompSize, mismatches, anomalies);

            if (local is not null)
            {
                long physicalCompSize = PhysicalCompressedSize(local, compSize);
                if (local.DataOffset + physicalCompSize > data.Length)
                {
                    anomalies.Add(
                        $"entry data [{local.DataOffset}..{local.DataOffset + physicalCompSize}) extends past the end of the archive at {data.Length}; truncated");
                }
            }

            entries.Add(new ZipEntryInfo
            {
                Index = index,
                Name = name,
                NameIsUtf8 = nameIsUtf8,
                PathAnomalies = pathAnomalies,
                Flags = flags,
                IsEncrypted = encrypted,
                CompressionMethod = method,
                Crc32 = crc,
                CompressedSize = compSize,
                UncompressedSize = uncompSize,
                LastModified = lastModified,
                LocalHeaderOffset = localOffset,
                LocalHeader = local,
                Mismatches = mismatches,
                Anomalies = anomalies,
            });

            pos = varEnd;
        }

        var archiveAnomalies = FindOverlaps(entries, cdOffset);

        var archive = new ZipArchiveInfo
        {
            Entries = entries,
            ArchiveAnomalies = archiveAnomalies,
            EndOfCentralDirectoryOffset = eocd,
            CentralDirectoryOffset = cdOffset,
            CentralDirectorySize = cdSize,
            DeclaredEntryCount = entriesTotal,
        };
        return ZipReadResult.From(reasons, archive);
    }

    /// <summary>
    /// Decompresses one entry into memory, under the deadline, the per-entry ratio guard and
    /// the shared total-expansion guard. Pass the same <paramref name="guard"/> across every
    /// read of one archive (or one nested walk) so a bomb split across entries is caught in
    /// aggregate; null means a fresh guard for a one-off read.
    /// </summary>
    public static ZipEntryDataResult ReadEntry(byte[] data, ZipEntryInfo entry, ScanBudget budget, ExpansionGuard? guard = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(budget);
        guard ??= new ExpansionGuard();

        if (entry.IsEncrypted)
        {
            // Present-but-unreadable, loudly. Skipping it silently is how a scan reports
            // clean on content it never saw (task brief).
            return ZipEntryDataResult.NotRead(
                OperationState.Incomplete,
                $"entry '{entry.Name}' is encrypted; content is present but unreadable without a key");
        }
        if (entry.LocalHeader is null)
        {
            return ZipEntryDataResult.NotRead(
                OperationState.Incomplete,
                $"entry '{entry.Name}': local header unreadable ({string.Join("; ", entry.Anomalies)})");
        }

        var clock = Stopwatch.StartNew();
        if (clock.Elapsed >= budget.Deadline)
        {
            return ZipEntryDataResult.NotRead(OperationState.Incomplete, "deadline exhausted before reading began");
        }

        ZipLocalHeaderInfo local = entry.LocalHeader;
        long dataOffset = local.DataOffset;
        long compSize = PhysicalCompressedSize(local, entry.CompressedSize);

        if (dataOffset + compSize > data.Length)
        {
            return ZipEntryDataResult.NotRead(
                OperationState.Incomplete,
                $"entry '{entry.Name}': data declares {compSize} bytes at {dataOffset} but the archive ends at {data.Length}; truncated");
        }

        ushort method = local.CompressionMethod;
        byte[] bytes;
        var notes = new List<string>();

        if (method == MethodStored)
        {
            if (guard.WouldExceed(compSize))
            {
                return ZipEntryDataResult.NotRead(
                    OperationState.Incomplete,
                    $"entry '{entry.Name}': {compSize} stored bytes would push total expanded output past the {guard.MaxTotalExpandedBytes}-byte cap");
            }
            bytes = new byte[compSize];
            Array.Copy(data, dataOffset, bytes, 0, compSize);
        }
        else if (method == MethodDeflate)
        {
            var inflated = Inflate(data, dataOffset, compSize, entry, budget, guard, clock);
            if (inflated.Result is not null)
            {
                return inflated.Result;
            }
            bytes = inflated.Bytes!;
        }
        else
        {
            return ZipEntryDataResult.NotRead(
                OperationState.Incomplete,
                $"entry '{entry.Name}': compression method {method} not supported (stored and deflate only)");
        }

        guard.Commit(bytes.LongLength);

        if (bytes.LongLength != entry.UncompressedSize)
        {
            notes.Add($"decompressed to {bytes.LongLength} bytes but the central directory declared {entry.UncompressedSize}");
        }
        if (local.HasDataDescriptor && local.UncompressedSize == 0)
        {
            // Data-descriptor entries carry real sizes after the data; the zeros in the
            // local header are structural, so only the central directory is comparable.
        }
        else if (bytes.LongLength != local.UncompressedSize)
        {
            notes.Add($"decompressed to {bytes.LongLength} bytes but the local header declared {local.UncompressedSize}");
        }

        uint actualCrc = Crc32.Compute(bytes);
        bool cdCrcOk = actualCrc == entry.Crc32;
        bool? localCrcOk = local.HasDataDescriptor && local.Crc32 == 0
            ? null
            : actualCrc == local.Crc32;
        if (!cdCrcOk)
        {
            notes.Add($"content CRC-32 is 0x{actualCrc:X8} but the central directory declared 0x{entry.Crc32:X8}");
        }
        if (localCrcOk == false)
        {
            notes.Add($"content CRC-32 is 0x{actualCrc:X8} but the local header declared 0x{local.Crc32:X8}");
        }

        return new ZipEntryDataResult(OperationState.Ok, null, bytes, cdCrcOk, localCrcOk, notes);
    }

    private static (ZipEntryDataResult? Result, byte[]? Bytes) Inflate(
        byte[] data,
        long dataOffset,
        long compSize,
        ZipEntryInfo entry,
        ScanBudget budget,
        ExpansionGuard guard,
        Stopwatch clock)
    {
        using var source = new MemoryStream(data, (int)dataOffset, (int)compSize, writable: false);
        using var inflater = new DeflateStream(source, CompressionMode.Decompress);
        using var output = new MemoryStream();
        byte[] chunk = new byte[ContainerLimits.DecompressChunkBytes];
        long produced = 0;
        long ratioDenominator = Math.Max(compSize, 1);

        while (true)
        {
            if (clock.Elapsed >= budget.Deadline)
            {
                return (ZipEntryDataResult.NotRead(
                    OperationState.Incomplete,
                    $"entry '{entry.Name}': deadline exhausted after {produced} decompressed bytes"), null);
            }

            int read;
            try
            {
                read = inflater.Read(chunk, 0, chunk.Length);
            }
            catch (InvalidDataException ex)
            {
                return (ZipEntryDataResult.NotRead(
                    OperationState.Failed,
                    $"entry '{entry.Name}': deflate data corrupt ({ex.Message})"), null);
            }
            if (read == 0)
            {
                break;
            }
            produced += read;

            // Guards run every chunk so a bomb is stopped mid-expansion, never after the
            // allocation it was designed to cause.
            if (guard.WouldExceed(produced))
            {
                return (ZipEntryDataResult.NotRead(
                    OperationState.Incomplete,
                    $"entry '{entry.Name}': total expanded output would pass the {guard.MaxTotalExpandedBytes}-byte cap after {produced} bytes; decompression bomb suspected"), null);
            }
            if (produced > ContainerLimits.RatioGuardFloorBytes &&
                produced > ContainerLimits.MaxCompressionRatio * ratioDenominator)
            {
                return (ZipEntryDataResult.NotRead(
                    OperationState.Incomplete,
                    $"entry '{entry.Name}': {compSize} compressed bytes expanded past {produced} bytes, over the {ContainerLimits.MaxCompressionRatio}:1 ratio cap; decompression bomb suspected"), null);
            }

            output.Write(chunk, 0, read);
        }

        // DeflateStream returning 0 with declared bytes unaccounted for means the bitstream
        // ended early inside an intact-length region — the data is malformed, distinct from
        // physical truncation which is caught before decompression starts.
        byte[] bytes = output.ToArray();
        return (null, bytes);
    }

    /// <summary>
    /// The size used to slice the entry's physical data: the local header's, because it sits
    /// adjacent to the data it describes — except when a data descriptor makes the local
    /// value a structural zero, where only the central directory has a value at all. Either
    /// source can lie; the actual-output guards in <see cref="ReadEntry"/> are the defence.
    /// </summary>
    private static long PhysicalCompressedSize(ZipLocalHeaderInfo local, uint cdCompressedSize) =>
        local.HasDataDescriptor && local.CompressedSize == 0 ? cdCompressedSize : local.CompressedSize;

    private static ZipLocalHeaderInfo? ReadLocalHeader(
        byte[] data,
        uint localOffset,
        string cdName,
        ushort cdFlags,
        ushort cdMethod,
        uint cdCrc,
        uint cdCompSize,
        uint cdUncompSize,
        List<string> mismatches,
        List<string> anomalies)
    {
        if ((long)localOffset + LocalHeaderFixedSize > data.Length)
        {
            anomalies.Add($"central directory points at local header offset {localOffset}, past the end of the archive at {data.Length}");
            return null;
        }
        if (U32(data, localOffset) != LocalHeaderSignature)
        {
            anomalies.Add($"no local header signature at declared offset {localOffset} (found 0x{U32(data, localOffset):X8})");
            return null;
        }

        ushort flags = (ushort)U16(data, localOffset + 6);
        ushort method = (ushort)U16(data, localOffset + 8);
        uint crc = U32(data, localOffset + 14);
        uint compSize = U32(data, localOffset + 18);
        uint uncompSize = U32(data, localOffset + 22);
        int nameLen = U16(data, localOffset + 26);
        int extraLen = U16(data, localOffset + 28);

        if ((long)localOffset + LocalHeaderFixedSize + nameLen + extraLen > data.Length)
        {
            anomalies.Add($"local header at {localOffset}: name and extra field run past the end of the archive");
            return null;
        }

        var localNameJunk = new List<string>();
        string name = DecodeName(
            data.AsSpan((int)(localOffset + LocalHeaderFixedSize), nameLen),
            (flags & FlagUtf8Name) != 0,
            localNameJunk);
        bool descriptor = (flags & FlagDataDescriptor) != 0;

        if (!string.Equals(name, cdName, StringComparison.Ordinal))
        {
            mismatches.Add($"name: central directory says '{cdName}', local header says '{name}'");
        }
        if (method != cdMethod)
        {
            mismatches.Add($"compression method: central directory says {cdMethod}, local header says {method}");
        }
        if (flags != cdFlags)
        {
            mismatches.Add($"flags: central directory says 0x{cdFlags:X4}, local header says 0x{flags:X4}");
        }

        // With a data descriptor the local sizes/CRC are legitimately zero — real values
        // follow the data — so zeros there are not a disagreement.
        if (!(descriptor && crc == 0))
        {
            if (crc != cdCrc)
            {
                mismatches.Add($"crc32: central directory says 0x{cdCrc:X8}, local header says 0x{crc:X8}");
            }
        }
        if (!(descriptor && compSize == 0))
        {
            if (compSize != cdCompSize)
            {
                mismatches.Add($"compressed size: central directory says {cdCompSize}, local header says {compSize}");
            }
        }
        if (!(descriptor && uncompSize == 0))
        {
            if (uncompSize != cdUncompSize)
            {
                mismatches.Add($"uncompressed size: central directory says {cdUncompSize}, local header says {uncompSize}");
            }
        }

        return new ZipLocalHeaderInfo
        {
            Name = name,
            Flags = flags,
            CompressionMethod = method,
            Crc32 = crc,
            CompressedSize = compSize,
            UncompressedSize = uncompSize,
            DataOffset = (long)localOffset + LocalHeaderFixedSize + nameLen + extraLen,
            HasDataDescriptor = descriptor,
        };
    }

    /// <summary>
    /// Flags overlapping entry data and entry data reaching into the central directory.
    /// Overlap is how one archive shows different content to different readers, so it is a
    /// signal, not just a defect.
    /// </summary>
    private static List<string> FindOverlaps(List<ZipEntryInfo> entries, uint cdOffset)
    {
        var anomalies = new List<string>();
        var ranges = new List<(long Start, long End, int Index)>();
        foreach (var e in entries)
        {
            if (e.LocalHeader is null)
            {
                continue;
            }
            long end = e.LocalHeader.DataOffset + PhysicalCompressedSize(e.LocalHeader, e.CompressedSize);
            ranges.Add((e.LocalHeaderOffset, end, e.Index));
            if (end > cdOffset)
            {
                anomalies.Add($"entry {e.Index} ('{e.Name}') data ends at {end}, inside the central directory at {cdOffset}");
            }
        }
        ranges.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.Index.CompareTo(b.Index));
        for (int i = 1; i < ranges.Count; i++)
        {
            if (ranges[i].Start < ranges[i - 1].End)
            {
                anomalies.Add(
                    $"entries {ranges[i - 1].Index} and {ranges[i].Index} overlap: [{ranges[i - 1].Start}..{ranges[i - 1].End}) vs [{ranges[i].Start}..{ranges[i].End})");
            }
        }
        return anomalies;
    }

    private static PathAnomalies ClassifyPath(string name)
    {
        var flags = PathAnomalies.None;
        if (name.Length > 0 && (name[0] == '/' || name[0] == '\\'))
        {
            flags |= PathAnomalies.AbsolutePath;
        }
        if (name.Length >= 2 && char.IsAsciiLetter(name[0]) && name[1] == ':')
        {
            flags |= PathAnomalies.DriveQualified;
        }
        foreach (var segment in name.Split('/', '\\'))
        {
            if (segment == "..")
            {
                flags |= PathAnomalies.ParentTraversal;
                break;
            }
        }
        foreach (char c in name)
        {
            if (c < 0x20 || c == 0x7F)
            {
                flags |= PathAnomalies.ContainsNulOrControl;
                break;
            }
        }
        return flags;
    }

    private static string DecodeName(ReadOnlySpan<byte> raw, bool utf8, List<string> anomalies)
    {
        if (utf8)
        {
            string decoded = Encoding.UTF8.GetString(raw);
            if (decoded.Contains('�'))
            {
                anomalies.Add("name declared UTF-8 (flag bit 11) but contains invalid UTF-8 sequences");
            }
            return decoded;
        }
        var chars = new char[raw.Length];
        for (int i = 0; i < raw.Length; i++)
        {
            byte b = raw[i];
            chars[i] = b < 0x80 ? (char)b : Cp437High[b - 0x80];
        }
        return new string(chars);
    }

    /// <summary>
    /// DOS timestamp: date bits 9–15 year-1980 / 5–8 month / 0–4 day; time bits 11–15 hour /
    /// 5–10 minute / 0–4 seconds÷2. Zero month or day — common in hostile archives — does
    /// not encode a date, so null rather than a made-up value.
    /// </summary>
    private static DateTime? DecodeDosDateTime(int dosDate, int dosTime)
    {
        int day = dosDate & 0x1F;
        int month = (dosDate >> 5) & 0x0F;
        int year = 1980 + (dosDate >> 9);
        int second = (dosTime & 0x1F) * 2;
        int minute = (dosTime >> 5) & 0x3F;
        int hour = (dosTime >> 11) & 0x1F;

        if (month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month) ||
            hour > 23 || minute > 59 || second > 59)
        {
            return null;
        }
        return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Unspecified);
    }

    private static int U16(byte[] data, long offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)offset, 2));

    private static uint U32(byte[] data, long offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)offset, 4));
}
