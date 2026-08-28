using Scythe.Core.Model;
using Scythe.Remediation;

namespace Scythe.Cli;

/// <summary>
/// Post-scan interactive remediation review (spec §6). The selection gates live in
/// RemediationPlanner and are re-enforced by RemediationExecutor — this class is only the
/// console conversation around them:
///  • auto-selected = CRITICAL/HIGH + executable action, nothing else (§6.1);
///  • "all" applies the same gate as auto-select (§6.5) — POSSIBLE/INFO are toggled one
///    at a time, each an individual operator decision;
///  • run_command findings are shown read-only and can never enter the batch (§6.8);
///  • nothing executes until the operator types the literal word CONFIRM (§6.9).
/// </summary>
public sealed class RemediationSession
{
    private readonly IReadOnlyList<Finding> _candidates;   // executable fix actions only
    private readonly IReadOnlyList<Finding> _displayOnly;  // run_command guidance
    private readonly HashSet<string> _selected;

    public RemediationSession(IReadOnlyList<Finding> findings)
    {
        _candidates = findings.Where(RemediationPlanner.IsManuallySelectable).ToList();
        _displayOnly = findings.Where(f => f.FixAction == FixAction.RunCommand).ToList();
        _selected = RemediationPlanner.AutoSelect(_candidates).Select(f => f.Id).ToHashSet();
    }

    public void Run()
    {
        if (_candidates.Count == 0 && _displayOnly.Count == 0)
        {
            Console.WriteLine("\nNo findings carry an actionable fix — nothing to remediate.");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("=== Remediation review ===");
        Console.WriteLine("Auto-selected items are CRITICAL/HIGH with a destructive fix (spec §6.1).");
        Console.WriteLine("POSSIBLE/INFO items are never pre-selected; toggle them individually if you");
        Console.WriteLine("have verified them yourself. Nothing runs until you type CONFIRM.");

        while (true)
        {
            PrintList();
            Console.Write("\n[#] toggle  [all] select all CRIT/HIGH  [none] clear  [show #] detail  [go] apply  [skip] exit > ");
            var input = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (input is null or "skip" or "q" or "quit") return;

            switch (input)
            {
                case "all":
                    // §6.5: bulk select filters on the SAME severity gate as auto-select.
                    _selected.Clear();
                    foreach (var f in RemediationPlanner.BulkSelect(_candidates)) _selected.Add(f.Id);
                    var skipped = _candidates.Count(f => !RemediationPlanner.QualifiesForAutoSelect(f));
                    if (skipped > 0)
                        Console.WriteLine($"  {skipped} POSSIBLE/INFO item(s) NOT selected by 'all' — toggle those individually.");
                    break;

                case "none":
                    _selected.Clear();
                    break;

                case "go":
                    if (_selected.Count == 0) { Console.WriteLine("  nothing selected."); break; }
                    if (Apply()) return;
                    break;

                default:
                    if (input.StartsWith("show "))
                        ShowDetail(input[5..]);
                    else
                        Toggle(input);
                    break;
            }
        }
    }

    private void PrintList()
    {
        Console.WriteLine();
        for (var n = 0; n < _candidates.Count; n++)
        {
            var f = _candidates[n];
            var mark = _selected.Contains(f.Id) ? "[x]" : "[ ]";
            var auto = RemediationPlanner.QualifiesForAutoSelect(f) ? "" : "  (manual-only)";
            Console.WriteLine($" {mark} {n + 1,3}. {f.Severity.ToString().ToUpperInvariant(),-8} {f.FixAction.ToWire(),-21} {Truncate(f.Target, 70)}{auto}");
        }

        if (_displayOnly.Count > 0)
        {
            Console.WriteLine("\n Operator-run-by-hand guidance (display-only, never executed — spec §6.8):");
            foreach (var f in _displayOnly)
                Console.WriteLine($"     - {f.Description}\n       > {f.FixParam}");
        }
    }

    private void Toggle(string input)
    {
        if (!int.TryParse(input, out var n) || n < 1 || n > _candidates.Count)
        {
            Console.WriteLine("  unrecognized input.");
            return;
        }
        var f = _candidates[n - 1];
        if (!_selected.Remove(f.Id))
        {
            if (!RemediationPlanner.QualifiesForAutoSelect(f))
            {
                // Individual operator decision for a below-gate finding: make them look at it.
                Console.WriteLine($"  {f.Severity.ToString().ToUpperInvariant()} finding — not auto-selectable. Review:");
                Console.WriteLine($"    {f.Description}");
                Console.WriteLine($"    action: {f.FixAction.ToWire()}  target: {f.FixParam ?? f.Target}");
                Console.Write("  select this item anyway? [y/N] > ");
                if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y") return;
            }
            _selected.Add(f.Id);
        }
    }

    private void ShowDetail(string arg)
    {
        if (!int.TryParse(arg.Trim(), out var n) || n < 1 || n > _candidates.Count)
        {
            Console.WriteLine("  show needs an item number.");
            return;
        }
        var f = _candidates[n - 1];
        Console.WriteLine($"\n  id:        {f.Id}");
        Console.WriteLine($"  severity:  {f.Severity.ToString().ToUpperInvariant()}");
        Console.WriteLine($"  group:     {f.Group}   check: {f.Check}");
        Console.WriteLine($"  desc:      {f.Description}");
        Console.WriteLine($"  target:    {f.Target}");
        Console.WriteLine($"  action:    {f.FixAction.ToWire()}   param: {f.FixParam}");
        if (f.Mitre is not null) Console.WriteLine($"  mitre:     {f.Mitre.TechniqueId} {f.Mitre.TechniqueName} ({f.Mitre.Tactic})");
        Console.WriteLine($"  hash-confirmed known-bad: {f.HashConfirmed}   vendor-trusted: {f.VendorTrusted}");
        if (f.FixAction == FixAction.DeleteFile && !f.HashConfirmed)
            Console.WriteLine("  note: not hash-confirmed — the engine will QUARANTINE (restorable) instead of delete (spec §6.4).");
    }

    /// <summary>Returns true when the session should end (batch ran or was abandoned).</summary>
    private bool Apply()
    {
        var batch = _candidates.Where(f => _selected.Contains(f.Id)).ToList();
        Console.WriteLine($"\nAbout to apply {batch.Count} action(s):");
        foreach (var f in batch)
            Console.WriteLine($"  - {f.FixAction.ToWire(),-21} {f.FixParam ?? f.Target}");
        Console.WriteLine("\nEvery action is written to the tamper-evident action log. Files not");
        Console.WriteLine("hash-confirmed known-bad are quarantined (restorable), not deleted.");
        Console.Write($"Type {ConfirmationGate.RequiredWord} to proceed, anything else to cancel > ");

        var typed = Console.ReadLine();
        if (!ConfirmationGate.IsConfirmed(typed))
        {
            Console.WriteLine("  not confirmed — no action taken.");
            return false;
        }

        var executor = new RemediationExecutor(new ActionLog(), new QuarantineVault());
        var results = executor.ExecuteBatch(batch, typed);

        Console.WriteLine();
        foreach (var r in results)
        {
            var tag = r.Status switch
            {
                ItemStatus.Done => "ok      ",
                ItemStatus.DoneQuarantinedInsteadOfDeleted => "ok(quar)",
                ItemStatus.Blocked => "BLOCKED ",
                ItemStatus.RefusedDisplayOnly => "refused ",
                _ => "FAILED  ",
            };
            Console.WriteLine($"  [{tag}] {r.Finding.FixParam ?? r.Finding.Target} — {r.Detail}");
        }
        Console.WriteLine($"\nAction log: {ScythePaths.ActionLogPath}");
        Console.WriteLine("Quarantined files can be restored with: scythescan vault restore <id>");
        return true;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
