using System.Diagnostics;
using Scythe.Core.Model;

namespace Scythe.Core.Scanning;

/// <summary>Runs scanners as numbered sequential phases with progress banners (spec §3/§7).
/// A scanner crash never kills the run and never reads as clean — it becomes an
/// Inconclusive check status for the whole phase.</summary>
public sealed class PhaseRunner
{
    private readonly IReadOnlyList<IScanner> _scanners;
    private readonly HashSet<string> _excludedGroups;
    private readonly Triage.EscalationEngine? _escalation;

    /// <param name="excludedGroups">Detection categories (scanner <see cref="IScanner.Group"/>
    /// names) the operator excluded via --only/--skip or a scan profile. The caller validates
    /// the names against the real scanner list; excluded phases are reported as Skipped
    /// checks — an operator-narrowed scan must never look like a full one (spec §6.7).</param>
    /// <param name="escalation">Optional in-run detection escalation: after each phase that
    /// executed, findings raised so far are mined for indicators armed detection-only into
    /// the custom.* sets (see <see cref="Triage.EscalationEngine"/> — no path into the §6
    /// remediation model). Null means no escalation, the historical behavior.</param>
    public PhaseRunner(IEnumerable<IScanner> scanners, IReadOnlyCollection<string>? excludedGroups = null,
        Triage.EscalationEngine? escalation = null)
    {
        _scanners = scanners.OrderBy(s => s.Phase).ToList();
        _excludedGroups = new HashSet<string>(excludedGroups ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        _escalation = escalation;
    }

    public void Run(ScanContext ctx, FindingCollector sink)
    {
        for (var i = 0; i < _scanners.Count; i++)
        {
            var scanner = _scanners[i];

            if (ctx.Cancel.IsCancellationRequested)
            {
                // This scanner (and everything after it) never started.
                ReportCancelledTail(sink, i);
                return;
            }

            if (_excludedGroups.Contains(scanner.Group))
            {
                sink.ReportCheck(new CheckStatus(scanner.Phase, scanner.Name, CheckOutcome.Skipped,
                    "phase excluded by operator scan selection (--only/--skip/profile) — this area was NOT checked"));
                continue;
            }

            if (scanner.MinDepth > ctx.Depth)
            {
                sink.ReportCheck(new CheckStatus(scanner.Phase, scanner.Name, CheckOutcome.Skipped,
                    $"requires {scanner.MinDepth} depth (running {ctx.Depth})"));
                continue;
            }

            ctx.Log.PhaseBanner(scanner.Phase, scanner.Name);
            sink.CurrentPhase = scanner.Phase;
            var before = sink.Findings.Count;
            var checksBefore = sink.Checks.Count;
            var sw = Stopwatch.StartNew();
            try
            {
                scanner.Run(ctx, sink);
                // Spec §6.7 backstop: a scanner that ran but reported no check status at all
                // would leave its whole area invisible — neither cleared nor flagged. The
                // convention is enforced here so one undisciplined scanner can't fake coverage.
                if (sink.Checks.Count == checksBefore)
                    sink.ReportCheck(new CheckStatus(scanner.Phase, scanner.Name, CheckOutcome.Inconclusive,
                        "scanner completed without reporting any check status — coverage cannot be confirmed"));
            }
            // Only OUR cancellation token ends the run; a stray OperationCanceledException
            // from a scanner-internal timeout is that phase's crash, not a scan-wide abort.
            catch (OperationCanceledException) when (ctx.Cancel.IsCancellationRequested)
            {
                sink.ReportCheck(new CheckStatus(scanner.Phase, scanner.Name, CheckOutcome.Inconclusive,
                    "scan cancelled mid-phase"));
                // The phase DID run (partially) — time was spent and partial findings may
                // exist, so record its timing (spec §7) before abandoning the run.
                sw.Stop();
                sink.ReportPhaseTiming(new PhaseTiming(scanner.Phase, scanner.Name, sw.Elapsed,
                    sink.Findings.Count - before));
                // The phases after this one never started — report them (spec §6.7).
                ReportCancelledTail(sink, i + 1);
                return;
            }
            catch (Exception ex)
            {
                // Spec §6.7: a phase that blew up did not complete — distinct from clean.
                sink.ReportCheck(new CheckStatus(scanner.Phase, scanner.Name, CheckOutcome.Inconclusive,
                    $"phase crashed: {ex.GetType().Name}: {ex.Message}"));
            }
            sw.Stop();
            // Machine-readable per-phase timing (spec §7) — completed and crashed phases alike;
            // skipped/excluded phases never reach here (they did not run).
            sink.ReportPhaseTiming(new PhaseTiming(scanner.Phase, scanner.Name, sw.Elapsed,
                sink.Findings.Count - before));
            ctx.Log.PhaseDone(scanner.Phase, scanner.Name, sw.Elapsed, sink.Findings.Count - before);
            // In-run detection escalation, BETWEEN phases and single-threaded — the only safe
            // point to mutate SignatureDb. Runs for every phase that EXECUTED, completed or
            // crashed alike (findings raised before a crash are still leads); the cancellation
            // path above returns without it — an abandoned run is not widened. Detection-only:
            // the engine arms POSSIBLE-severity indicators with no fix action, nothing more.
            if (_escalation is not null)
            {
                _escalation.ProcessNewFindings(scanner.Phase, sink.Findings);
                // Later phases that hit one of these indicators are not independent evidence;
                // the collector marks them so correlation cannot corroborate a finding with
                // its own descendants.
                sink.NoteArmedLeads(_escalation.Leads);
            }
        }
    }

    /// <summary>Reports every scanner from <paramref name="firstNotRun"/> onward as Skipped.
    /// Spec §6.7: a cancelled run must never let the phases that had not yet started silently
    /// vanish from the report — an area that was not checked must be visible as not checked.
    /// All not-yet-run scanners get the same cancellation message, including ones an
    /// exclusion or depth gate would have skipped anyway — the statement "not run because the
    /// scan was cancelled first" is true for all of them, and one uniform message keeps this
    /// path simple to audit.</summary>
    private void ReportCancelledTail(FindingCollector sink, int firstNotRun)
    {
        for (var i = firstNotRun; i < _scanners.Count; i++)
        {
            sink.ReportCheck(new CheckStatus(_scanners[i].Phase, _scanners[i].Name, CheckOutcome.Skipped,
                "not run — scan cancelled before this phase started (operator interrupt or " +
                "--max-minutes deadline); this area was NOT checked"));
        }
    }
}
