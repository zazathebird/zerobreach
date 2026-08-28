using Scythe.Remediation;
using static Scythe.Tests.TestHelpers;

namespace Scythe.Tests;

/// <summary>Spec §6.10 — append-only, hash-chained, tamper-evident.</summary>
public class ActionLogTests
{
    [Fact]
    public void Chain_appends_and_verifies()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);

        var e1 = log.Append("quarantine", @"C:\x\a.exe", "ok");
        var e2 = log.Append("delete_registry_value", @"HKCU\Run::x", "ok");

        Assert.Equal(ActionLog.GenesisHash, e1.PrevHash);
        Assert.Equal(e1.Hash, e2.PrevHash);
        Assert.Equal(1, e1.Seq);
        Assert.Equal(2, e2.Seq);
        Assert.True(log.Verify(out _, out _));
    }

    [Fact]
    public void Editing_a_past_entry_breaks_verification()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("quarantine", @"C:\x\a.exe", "ok");
        log.Append("quarantine", @"C:\x\b.exe", "ok");

        var lines = File.ReadAllLines(path);
        lines[0] = lines[0].Replace(@"a.exe", @"z.exe");
        File.WriteAllLines(path, lines);

        Assert.False(log.Verify(out var broken, out _));
        Assert.Equal(1, broken);
    }

    [Fact]
    public void Removing_an_entry_breaks_verification()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("a", "t1", "ok");
        log.Append("b", "t2", "ok");
        log.Append("c", "t3", "ok");

        var lines = File.ReadAllLines(path);
        File.WriteAllLines(path, new[] { lines[0], lines[2] });

        Assert.False(log.Verify(out var broken, out _));
        Assert.Equal(3, broken);
    }

    [Fact]
    public void Empty_or_missing_log_is_a_valid_chain()
    {
        var log = new ActionLog(Path.Combine(NewScratchDir(), "never-created.jsonl"));
        Assert.True(log.Verify(out _, out _));
    }

    [Fact]
    public void Truncating_the_log_breaks_verification()
    {
        // A hash chain alone cannot see this: lopping entries off the end leaves a shorter
        // chain whose every link still verifies. Without the anchor, an operator could erase
        // the record of what was destroyed and still pass "log verify".
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("quarantine", @"C:\x\a.exe", "ok");
        log.Append("delete_file", @"C:\x\b.exe", "ok");
        log.Append("purge_from_vault", @"C:\x\c.exe", "ok");

        var lines = File.ReadAllLines(path);
        File.WriteAllLines(path, lines.Take(1));   // drop the last two entries

        var result = log.VerifyChain();

        Assert.False(result.Ok);
        Assert.Equal(ActionLog.ChainState.Truncated, result.State);
        Assert.Contains("TRUNCATED", result.Why);
    }

    [Fact]
    public void Deleting_the_whole_log_breaks_verification()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("quarantine", @"C:\x\a.exe", "ok");

        File.Delete(path);

        var result = log.VerifyChain();
        Assert.Equal(ActionLog.ChainState.Truncated, result.State);
        Assert.False(log.Verify(out _, out _));
    }

    [Fact]
    public void A_log_without_its_anchor_is_unverifiable_not_ok()
    {
        // Spec §6.7: the links verify, but completeness cannot be proven, so this must not be
        // reported as a clean chain.
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("quarantine", @"C:\x\a.exe", "ok");

        File.Delete(path + ".anchor");

        var result = log.VerifyChain();
        Assert.Equal(ActionLog.ChainState.Unverifiable, result.State);
        Assert.False(result.Ok);
    }

    [Fact]
    public void A_corrupt_anchor_is_unverifiable_not_ok()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("quarantine", @"C:\x\a.exe", "ok");
        File.WriteAllText(path + ".anchor", "{not json");

        Assert.Equal(ActionLog.ChainState.Unverifiable, log.VerifyChain().State);
    }

    [Fact]
    public void An_intact_chain_reports_its_entry_count()
    {
        var path = Path.Combine(NewScratchDir(), "log.jsonl");
        var log = new ActionLog(path);
        log.Append("a", "t1", "ok");
        log.Append("b", "t2", "ok");

        var result = log.VerifyChain();
        Assert.Equal(ActionLog.ChainState.Intact, result.State);
        Assert.Equal(2, result.Entries);
        Assert.True(result.Ok);
    }

    [Fact]
    public void A_never_used_log_verifies_without_an_anchor()
    {
        // No log and no anchor means no remediation has ever run — a fresh install must not
        // report tamper evidence. It is only once an anchor exists that a missing or short
        // log becomes evidence.
        var log = new ActionLog(Path.Combine(NewScratchDir(), "fresh.jsonl"));
        var result = log.VerifyChain();

        Assert.Equal(ActionLog.ChainState.Intact, result.State);
        Assert.Equal(0, result.Entries);
    }
}
