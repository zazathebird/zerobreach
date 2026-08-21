using ZeroBreach.Cli;
using ZeroBreach.Core.Scanning;

namespace ZeroBreach.Tests;

/// <summary>Custom-scan flags and profile precedence: what the operator TYPES always beats
/// what a profile file says.</summary>
public class CliOptionsTests
{
    [Fact]
    public void Only_and_skip_parse_as_trimmed_deduplicated_lists()
    {
        var o = CliOptions.Parse(new[] { "--only", "Persistence, C2,persistence" }, out var err);
        Assert.Null(err);
        Assert.Equal(new[] { "Persistence", "C2" }, o.Only);

        o = CliOptions.Parse(new[] { "--skip", "EventLog,ContentScan" }, out err);
        Assert.Null(err);
        Assert.Equal(new[] { "EventLog", "ContentScan" }, o.Skip);
    }

    [Fact]
    public void Only_and_skip_cannot_be_combined()
    {
        CliOptions.Parse(new[] { "--only", "C2", "--skip", "EventLog" }, out var err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Empty_category_list_is_an_error()
    {
        CliOptions.Parse(new[] { "--only", "," }, out var err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Profile_fills_in_unset_options()
    {
        var o = CliOptions.Parse(new[] { "--profile", "x.json" }, out var err);
        Assert.Null(err);
        Assert.True(o.ApplyProfile(new ScanProfile
        {
            Mode = "DEEP",
            SinceHours = 24,
            Only = new List<string> { "Persistence" },
            IocFile = "/tmp/iocs.txt",
            Html = true,
        }, out _));

        Assert.Equal("DEEP", o.Mode);
        Assert.Equal(24, o.SinceHours);
        Assert.Equal(new[] { "Persistence" }, o.Only);
        Assert.Equal("/tmp/iocs.txt", o.IocFile);
        Assert.True(o.Html);
    }

    [Fact]
    public void Explicitly_typed_flags_override_the_profile()
    {
        var o = CliOptions.Parse(
            new[] { "--mode", "QUICK", "--since-hours", "6", "--profile", "x.json" }, out var err);
        Assert.Null(err);
        Assert.True(o.ApplyProfile(new ScanProfile { Mode = "DEEP", SinceHours = 48 }, out _));
        Assert.Equal("QUICK", o.Mode);
        Assert.Equal(6, o.SinceHours);
    }

    [Fact]
    public void Cli_category_selection_replaces_the_profiles_selection_entirely()
    {
        // Half-merging a profile's "only" with a typed "--skip" would produce a scan
        // nobody asked for — typed selection wins as one unit.
        var o = CliOptions.Parse(new[] { "--skip", "EventLog", "--profile", "x.json" }, out _);
        Assert.True(o.ApplyProfile(new ScanProfile { Only = new List<string> { "C2" } }, out _));
        Assert.Empty(o.Only);
        Assert.Equal(new[] { "EventLog" }, o.Skip);
    }

    [Fact]
    public void Profile_stealth_mode_conflicts_with_typed_interactive()
    {
        var o = CliOptions.Parse(new[] { "-i", "--profile", "x.json" }, out var err);
        Assert.Null(err);
        Assert.False(o.ApplyProfile(new ScanProfile { Mode = "STEALTH" }, out var mergeErr));
        Assert.NotNull(mergeErr);
    }

    [Fact]
    public void Save_profile_round_trips_through_load()
    {
        var dir = TestHelpers.NewScratchDir();
        var o = CliOptions.Parse(
            new[] { "--mode", "FULL", "--since-hours", "12", "--skip", "EventLog", "--html" }, out var err);
        Assert.Null(err);

        var path = Path.Combine(dir, "my-scan.json");
        File.WriteAllText(path, o.ToProfile("my-scan").ToJson());
        var p = ScanProfile.Load(path);

        Assert.Equal("my-scan", p.Name);
        Assert.Equal("FULL", p.Mode);
        Assert.Equal(12, p.SinceHours);
        Assert.Equal(new[] { "EventLog" }, p.Skip);
        Assert.True(p.Html);
    }

    [Fact]
    public void Extract_iocs_parses_and_is_rejected_in_stealth()
    {
        var o = CliOptions.Parse(new[] { "--extract-iocs", "alert.txt" }, out var err);
        Assert.Null(err);
        Assert.Equal("alert.txt", o.ExtractIocsFile);

        // Spec §6.6: per-indicator confirmation needs a console, so no STEALTH — typed...
        CliOptions.Parse(new[] { "--mode", "STEALTH", "--extract-iocs", "alert.txt" }, out err);
        Assert.NotNull(err);

        // ...or via a profile that flips the mode after parse.
        o = CliOptions.Parse(new[] { "--extract-iocs", "alert.txt", "--profile", "x.json" }, out err);
        Assert.Null(err);
        Assert.False(o.ApplyProfile(new ScanProfile { Mode = "STEALTH" }, out var mergeErr));
        Assert.NotNull(mergeErr);
    }

    [Fact]
    public void Categories_command_and_vault_purge_parse()
    {
        var o = CliOptions.Parse(new[] { "categories" }, out var err);
        Assert.Null(err);
        Assert.Equal("categories", o.Command);

        o = CliOptions.Parse(new[] { "vault", "purge", "20260819_abc" }, out err);
        Assert.Null(err);
        Assert.Equal("vault", o.Command);
        Assert.Equal("purge", o.SubCommand);
        Assert.Equal("20260819_abc", o.SubArgument);
    }

    [Fact]
    public void Triage_flags_parse_and_are_scoped_to_the_triage_command()
    {
        var o = CliOptions.Parse(new[] { "triage", "--symptoms", "ransom note", "--llm-assist" }, out var err);
        Assert.Null(err);
        Assert.Equal("triage", o.Command);
        Assert.Equal("ransom note", o.SymptomsText);
        Assert.True(o.LlmAssist);

        // Both symptom sources at once is ambiguous.
        CliOptions.Parse(new[] { "triage", "--symptoms", "x", "--symptoms-file", "f.txt" }, out err);
        Assert.NotNull(err);

        // Triage-only flags on a plain scan are an error, not silently ignored.
        CliOptions.Parse(new[] { "--symptoms", "ransom note" }, out err);
        Assert.NotNull(err);

        // Deriving/confirming a plan is a console conversation — no STEALTH.
        CliOptions.Parse(new[] { "triage", "--mode", "STEALTH", "--symptoms", "x" }, out err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Adaptive_flag_parses_on_plain_scans()
    {
        var o = CliOptions.Parse(new[] { "--adaptive", "--mode", "FULL" }, out var err);
        Assert.Null(err);
        Assert.True(o.Adaptive);
        Assert.DoesNotContain("adaptive", o.ToProfile("x").ToJson(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_flag_is_never_swallowed_as_another_flags_value()
    {
        // `--case --html` must error, not set CaseId="--html" and silently drop the report.
        CliOptions.Parse(new[] { "--case", "--html" }, out var err);
        Assert.NotNull(err);
        CliOptions.Parse(new[] { "--output-dir", "-i" }, out err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Trailing_arguments_after_a_subcommand_are_rejected()
    {
        CliOptions.Parse(new[] { "vault", "purge", "abc", "--dry-run" }, out var err);
        Assert.NotNull(err);
        CliOptions.Parse(new[] { "log", "verify", "extra" }, out err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Max_minutes_case_and_operator_parse()
    {
        var o = CliOptions.Parse(
            new[] { "--max-minutes", "45", "--case", "INC-2026-081", "--operator", "pat" }, out var err);
        Assert.Null(err);
        Assert.Equal(45, o.MaxMinutes);
        Assert.Equal("INC-2026-081", o.CaseId);
        Assert.Equal("pat", o.OperatorName);

        CliOptions.Parse(new[] { "--max-minutes", "0" }, out err);
        Assert.NotNull(err);
        CliOptions.Parse(new[] { "--max-minutes", "soon" }, out err);
        Assert.NotNull(err);
    }

    [Fact]
    public void Report_show_and_rules_lint_parse_as_subcommands()
    {
        var o = CliOptions.Parse(new[] { "report", "show", "run.json.gz" }, out var err);
        Assert.Null(err);
        Assert.Equal(("report", "show", "run.json.gz"), (o.Command, o.SubCommand, o.SubArgument));

        o = CliOptions.Parse(new[] { "rules", "lint", "custom.json" }, out err);
        Assert.Null(err);
        Assert.Equal(("rules", "lint", "custom.json"), (o.Command, o.SubCommand, o.SubArgument));

        o = CliOptions.Parse(new[] { "vault", "verify" }, out err);
        Assert.Null(err);
        Assert.Equal(("vault", "verify"), (o.Command, o.SubCommand));
    }

    [Fact]
    public void Per_run_metadata_and_deadline_never_leak_into_a_saved_profile()
    {
        // Case id, operator, and a time budget describe ONE engagement run — a reusable
        // profile must not preconfigure them.
        var o = CliOptions.Parse(
            new[] { "--case", "INC-1", "--operator", "pat", "--max-minutes", "30", "--mode", "FULL" }, out var err);
        Assert.Null(err);
        var json = o.ToProfile("x").ToJson();
        Assert.DoesNotContain("case", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("operator", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("minutes", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Extract_iocs_never_leaks_into_a_saved_profile()
    {
        // Arming text-extracted IOCs is a per-run, per-indicator decision (spec §6.6) —
        // a profile file must not be able to preconfigure it.
        var o = CliOptions.Parse(new[] { "--extract-iocs", "alert.txt", "--mode", "FULL" }, out var err);
        Assert.Null(err);
        Assert.DoesNotContain("extract", o.ToProfile("x").ToJson(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Saved_profile_never_carries_per_run_opt_ins()
    {
        // --load-hives / --interactive / baselines on the command line must NOT leak into
        // a saved profile (spec §4: hive loading is an explicit per-run opt-in).
        var o = CliOptions.Parse(
            new[] { "--load-hives", "-i", "--baseline", "b.json", "--mode", "DEEP" }, out var err);
        Assert.Null(err);
        var json = o.ToProfile("x").ToJson();
        Assert.DoesNotContain("loadHives", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("interactive", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("baseline", json, StringComparison.OrdinalIgnoreCase);
    }
}
