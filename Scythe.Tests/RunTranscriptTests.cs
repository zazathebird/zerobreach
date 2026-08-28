using System.Text;
using Scythe.Cli;
using Scythe.Core.Scanning;

namespace Scythe.Tests;

/// <summary>
/// `--log &lt;path&gt;` — the console transcript (spec: the one output artifact a run did not
/// leave behind). These tests redirect the process console, so they assert with Contains
/// rather than exact equality: xUnit may be running another class concurrently and its
/// output is allowed to land in the same buffer.
/// </summary>
public class RunTranscriptTests
{
    [Fact]
    public void Log_flag_parses_to_a_path()
    {
        var o = CliOptions.Parse(new[] { "--log", @"C:\cases\run.txt" }, out var err);
        Assert.Null(err);
        Assert.Equal(@"C:\cases\run.txt", o.LogFile);
    }

    [Fact]
    public void Log_flag_requires_a_value_and_will_not_swallow_the_next_option()
    {
        CliOptions.Parse(new[] { "--log" }, out var err);
        Assert.Contains("--log requires a value", err);

        // `--log --html` must be an error, not a transcript named "--html" plus a silently
        // missing HTML report.
        CliOptions.Parse(new[] { "--log", "--html" }, out err);
        Assert.Contains("looks like another option", err);
    }

    [Fact]
    public void Log_is_refused_in_stealth_mode_whichever_order_it_is_typed()
    {
        // Order matters: --log parsed first means the mode is not yet known, so the check
        // has to live after the loop rather than in the flag's own case.
        foreach (var args in new[]
                 {
                     new[] { "--mode", "STEALTH", "--log", "run.txt" },
                     new[] { "--log", "run.txt", "--mode", "STEALTH" },
                 })
        {
            CliOptions.Parse(args, out var err);
            Assert.NotNull(err);
            Assert.Contains("--log", err);
            Assert.Contains("STEALTH", err);
        }
    }

    [Fact]
    public void A_profile_that_turns_the_run_stealth_also_refuses_the_log()
    {
        // The parse-time check cannot see this: --mode is not on the command line, so the
        // run only becomes STEALTH when the profile merges in.
        var o = CliOptions.Parse(new[] { "--log", "run.txt" }, out var err);
        Assert.Null(err);
        Assert.False(o.ApplyProfile(new ScanProfile { Name = "p", Mode = "STEALTH" }, out var mergeError));
        Assert.Contains("--log", mergeError);
    }

    [Fact]
    public void A_saved_profile_never_carries_the_transcript_path()
    {
        // A transcript path is a per-run decision, like --interactive and the baselines.
        // A profile that silently re-pointed every future run's log at one operator's
        // case folder would overwrite it.
        var o = CliOptions.Parse(new[] { "--mode", "DEEP", "--log", @"C:\cases\alice\run.txt" }, out var err);
        Assert.Null(err);
        var json = System.Text.Json.JsonSerializer.Serialize(o.ToProfile("p"));
        Assert.DoesNotContain("alice", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("run.txt", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Transcript_captures_stdout_and_stderr_and_restores_the_console()
    {
        var dir = TestHelpers.NewScratchDir();
        var path = Path.Combine(dir, "run.txt");
        var before = Console.Out;

        using (RunTranscript.Start(path, "9.9.9", new[] { "--mode", "DEEP" }))
        {
            Console.WriteLine("SCYTHETEST-stdout-line");
            Console.Error.WriteLine("SCYTHETEST-stderr-line");
        }

        Assert.Same(before, Console.Out);

        var text = File.ReadAllText(path);
        Assert.Contains("SCYTHETEST-stdout-line", text);
        // An error belongs in the transcript: the failure case is the main reason to read one.
        Assert.Contains("SCYTHETEST-stderr-line", text);
        // Provenance — which build, which machine, which command line.
        Assert.Contains("Scythe 9.9.9", text);
        Assert.Contains("scythescan --mode DEEP", text);
        Assert.Contains(Environment.MachineName, text);
        Assert.Contains("# finished:", text);
    }

    [Fact]
    public void Transcript_still_reaches_the_real_console()
    {
        var dir = TestHelpers.NewScratchDir();
        var path = Path.Combine(dir, "run.txt");
        var captured = new StringWriter();
        var before = Console.Out;
        Console.SetOut(captured);
        try
        {
            using (RunTranscript.Start(path, "1.0.0", Array.Empty<string>()))
                Console.WriteLine("SCYTHETEST-tee");
        }
        finally { Console.SetOut(before); }

        Assert.Contains("SCYTHETEST-tee", captured.ToString());
        Assert.Contains("SCYTHETEST-tee", File.ReadAllText(path));
    }

    [Fact]
    public void Transcript_is_readable_while_the_run_is_still_going()
    {
        // AutoFlush + FileShare.Read. A scan that is cancelled or killed must still leave a
        // complete transcript, and an operator watching a long DEEP run should be able to
        // tail it. Buffering would lose exactly the tail that explains what happened.
        var dir = TestHelpers.NewScratchDir();
        var path = Path.Combine(dir, "run.txt");
        using (RunTranscript.Start(path, "1.0.0", Array.Empty<string>()))
        {
            Console.WriteLine("SCYTHETEST-midrun");
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            Assert.Contains("SCYTHETEST-midrun", sr.ReadToEnd());
        }
    }

    [Fact]
    public void Transcript_creates_a_missing_parent_directory()
    {
        var dir = TestHelpers.NewScratchDir();
        var path = Path.Combine(dir, "nested", "deeper", "run.txt");
        using (RunTranscript.Start(path, "1.0.0", Array.Empty<string>()))
            Console.WriteLine("SCYTHETEST-nested");
        Assert.Contains("SCYTHETEST-nested", File.ReadAllText(path));
    }

    [Fact]
    public void An_unusable_transcript_path_throws_rather_than_silently_dropping_the_log()
    {
        // Program turns this into `error: --log path unusable` and exits 1 BEFORE the scan,
        // rather than discovering it after a 40-minute DEEP run.
        var dir = TestHelpers.NewScratchDir();
        var before = Console.Out;
        Assert.ThrowsAny<Exception>(() => RunTranscript.Start(dir, "1.0.0", Array.Empty<string>()));
        // A failed Start must leave the console alone — there is no transcript to restore
        // from, so a half-installed tee would send the rest of the run into a dead writer.
        Assert.Same(before, Console.Out);
    }

    [Fact]
    public void Transcript_is_utf8_with_a_bom()
    {
        // Windows-only product; the operator opens this in Notepad and pastes it into a
        // ticket. A BOM is what keeps non-ASCII output from arriving as mojibake.
        var dir = TestHelpers.NewScratchDir();
        var path = Path.Combine(dir, "run.txt");
        using (RunTranscript.Start(path, "1.0.0", Array.Empty<string>()))
            Console.WriteLine("SCYTHETEST-\u2014-emdash");

        var bytes = File.ReadAllBytes(path);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes.Take(3).ToArray());
        Assert.Contains("\u2014", new UTF8Encoding(false).GetString(bytes));
    }
}
