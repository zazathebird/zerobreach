namespace Scythe.Diff.Tests;

using System.Text;

/// <summary>Fixture builders and a deep renderer shared by the test classes.</summary>
internal static class TestData
{
    public const string Machine = "machine-A";
    public static readonly DateTimeOffset BaselineTime = new(2026, 07, 01, 12, 0, 0, TimeSpan.Zero);
    public static readonly DateTimeOffset CurrentTime = new(2026, 08, 01, 12, 0, 0, TimeSpan.Zero);

    public static RunRecord Run(
        IReadOnlyList<Finding>? findings = null,
        IReadOnlyList<CheckResult>? checks = null,
        string machine = Machine,
        DateTimeOffset? timestamp = null,
        string mode = "deep")
        => new(machine, timestamp ?? CurrentTime, mode,
               checks ?? new[] { Check("chk.autoruns") },
               findings ?? Array.Empty<Finding>());

    public static RunRecord BaselineRun(
        IReadOnlyList<Finding>? findings = null,
        IReadOnlyList<CheckResult>? checks = null,
        string machine = Machine,
        DateTimeOffset? timestamp = null,
        string mode = "deep")
        => Run(findings, checks, machine, timestamp ?? BaselineTime, mode);

    public static Finding Finding(
        string id,
        FindingSeverity severity = FindingSeverity.Medium,
        string description = "a finding",
        string category = "autorun",
        string target = @"C:\Windows\evil.exe",
        IReadOnlyDictionary<string, string>? properties = null)
        => new(id, category, target, severity, description, properties);

    public static CheckResult Check(string id, CheckStatus status = CheckStatus.Completed, string? reason = null)
        => new(id, status, reason);

    /// <summary>
    /// Canonical deep rendering of a run record: value-by-value, in stored order, so two
    /// renders taken before and after a diff prove the input was not mutated (including
    /// element order), and property enumeration is sorted so the render itself is stable.
    /// </summary>
    public static string Render(RunRecord record)
    {
        var sb = new StringBuilder();
        sb.Append(record.MachineId).Append('|').Append(record.Timestamp.ToString("O"))
          .Append('|').Append(record.ScanMode).Append('\n');
        foreach (var check in record.Checks)
        {
            sb.Append("check:").Append(check.CheckId).Append('=').Append(check.Status)
              .Append(':').Append(check.Reason ?? "<null>").Append('\n');
        }

        foreach (var finding in record.Findings)
        {
            sb.Append("finding:").Append(finding.Id).Append('|').Append(finding.Category)
              .Append('|').Append(finding.Target).Append('|').Append(finding.Severity)
              .Append('|').Append(finding.Description);
            if (finding.Properties is { } props)
            {
                foreach (var key in props.Keys.Order(StringComparer.Ordinal))
                {
                    sb.Append('|').Append(key).Append('=').Append(props[key]);
                }
            }

            sb.Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>Canonical deep rendering of a diff result, for determinism assertions.</summary>
    public static string Render(DiffResult result)
    {
        var sb = new StringBuilder();
        sb.Append("state:").Append(result.State).Append('\n');
        sb.Append("error:").Append(result.Error ?? "<null>").Append('\n');
        foreach (var warning in result.Warnings)
        {
            sb.Append("warn:").Append(warning).Append('\n');
        }

        AppendFindings(sb, "new", result.NewFindings);
        AppendFindings(sb, "resolved", result.ResolvedFindings);
        AppendFindings(sb, "persisting", result.PersistingFindings);
        foreach (var changed in result.ChangedFindings)
        {
            sb.Append("changed:").Append(changed.Current.Id).Append('\n');
            foreach (var change in changed.Changes)
            {
                sb.Append("  field:").Append(change.Field)
                  .Append('|').Append(change.BaselineValue ?? "<null>")
                  .Append('|').Append(change.CurrentValue ?? "<null>").Append('\n');
            }
        }

        foreach (var delta in result.CoverageDeltas)
        {
            sb.Append("coverage:").Append(delta.CheckId).Append('|').Append(delta.Kind)
              .Append('|').Append(delta.BaselineStatus?.ToString() ?? "<null>")
              .Append('|').Append(delta.BaselineReason ?? "<null>")
              .Append('|').Append(delta.CurrentStatus?.ToString() ?? "<null>")
              .Append('|').Append(delta.CurrentReason ?? "<null>").Append('\n');
        }

        return sb.ToString();
    }

    private static void AppendFindings(StringBuilder sb, string label, IReadOnlyList<Finding> findings)
    {
        foreach (var finding in findings)
        {
            sb.Append(label).Append(':').Append(finding.Id).Append('|')
              .Append(finding.Severity).Append('|').Append(finding.Description).Append('\n');
        }
    }
}
