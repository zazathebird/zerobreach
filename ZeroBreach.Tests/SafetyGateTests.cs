using ZeroBreach.Core.Model;
using ZeroBreach.Remediation;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>Spec §6.1 / §6.5 / §6.9 — the selection and confirmation gates.</summary>
public class SafetyGateTests
{
    [Theory]
    [InlineData(Severity.Critical, FixAction.DeleteFile, true)]
    [InlineData(Severity.Critical, FixAction.Quarantine, true)]
    [InlineData(Severity.High, FixAction.KillProcess, true)]
    [InlineData(Severity.High, FixAction.DeleteRegistryValue, true)]
    // POSSIBLE/INFO are never auto-selected, whatever the action:
    [InlineData(Severity.Possible, FixAction.DeleteFile, false)]
    [InlineData(Severity.Possible, FixAction.Quarantine, false)]
    [InlineData(Severity.Info, FixAction.DeleteFile, false)]
    // run_command and none are never auto-selected, whatever the severity:
    [InlineData(Severity.Critical, FixAction.RunCommand, false)]
    [InlineData(Severity.Critical, FixAction.None, false)]
    public void AutoSelect_gate(Severity sev, FixAction fix, bool expected) =>
        Assert.Equal(expected, RemediationPlanner.QualifiesForAutoSelect(MakeFinding(sev, fix)));

    [Fact]
    public void BulkSelect_applies_the_same_gate_as_auto_select()
    {
        var findings = new[]
        {
            MakeFinding(Severity.Critical, FixAction.DeleteFile, discriminator: "a"),
            MakeFinding(Severity.High, FixAction.Quarantine, discriminator: "b"),
            // §6.5: an INFO finding with a destructive fix_param exists to be read and
            // typed by hand — a bulk action must never queue it.
            MakeFinding(Severity.Info, FixAction.DeleteFile, discriminator: "c"),
            MakeFinding(Severity.Possible, FixAction.KillProcess, discriminator: "d"),
            MakeFinding(Severity.Critical, FixAction.RunCommand, discriminator: "e"),
        };

        var bulk = RemediationPlanner.BulkSelect(findings);

        Assert.Equal(2, bulk.Count);
        Assert.All(bulk, f => Assert.True(f.Severity >= Severity.High && f.FixAction.IsExecutable()));
        Assert.Equal(RemediationPlanner.AutoSelect(findings).Select(f => f.Id),
                     bulk.Select(f => f.Id));
    }

    [Fact]
    public void Manual_selection_allows_any_severity_but_never_run_command()
    {
        Assert.True(RemediationPlanner.IsManuallySelectable(MakeFinding(Severity.Info, FixAction.Quarantine)));
        Assert.False(RemediationPlanner.IsManuallySelectable(MakeFinding(Severity.Critical, FixAction.RunCommand)));
        Assert.False(RemediationPlanner.IsManuallySelectable(MakeFinding(Severity.Critical, FixAction.None)));
    }

    [Theory]
    [InlineData("CONFIRM", true)]
    [InlineData("  CONFIRM  ", true)]  // surrounding whitespace is forgiven
    [InlineData("confirm", false)]     // case-sensitive on purpose
    [InlineData("CONFIRM.", false)]
    [InlineData("y", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Typed_confirmation_is_exact(string? typed, bool expected) =>
        Assert.Equal(expected, ConfirmationGate.IsConfirmed(typed));
}
