using System.Collections.Concurrent;
using Scythe.Core.Model;
using Scythe.Core.Triage;

namespace Scythe.Core.Scanning;

public sealed class FindingCollector : IFindingSink
{
    private readonly ConcurrentDictionary<string, Finding> _findings = new();
    private readonly ConcurrentQueue<CheckStatus> _checks = new();
    private readonly ConcurrentQueue<PhaseTiming> _phaseTimings = new();

    /// <summary>Indicators armed mid-run by escalation, with the phase after which each was
    /// armed. Only ever appended between phases (single-threaded), read during Report.</summary>
    private readonly List<Lead> _armedLeads = new();

    public Action<Finding>? OnFinding { get; set; }

    /// <summary>Phase currently executing, set by <see cref="PhaseRunner"/>. Used to decide
    /// whether a finding could possibly have come from an escalation-armed indicator.</summary>
    public int CurrentPhase { get; internal set; }

    public void Report(Finding finding)
    {
        StampDerivation(finding);
        if (_findings.TryAdd(finding.Id, finding))
            OnFinding?.Invoke(finding);
    }

    public void ReportCheck(CheckStatus status) => _checks.Enqueue(status);

    public void ReportPhaseTiming(PhaseTiming timing) => _phaseTimings.Enqueue(timing);

    /// <summary>Records the indicators escalation has armed so far. Called between phases by
    /// <see cref="PhaseRunner"/>; the full lead list is passed each time and only unseen
    /// entries are kept.</summary>
    internal void NoteArmedLeads(IReadOnlyList<Lead> leads)
    {
        for (var i = _armedLeads.Count; i < leads.Count; i++)
            _armedLeads.Add(leads[i]);
    }

    /// <summary>Marks a finding that a LATER phase raised on an artifact an EARLIER phase's
    /// finding had armed as an indicator. Attribution is deliberately generous — matching the
    /// indicator against the finding's target/fix param is enough — because the only effect is
    /// to withhold a correlation-driven severity increase, and over-withholding is the safe
    /// direction. The phase comparison keeps a finding from being marked by an indicator its
    /// own phase armed.</summary>
    private void StampDerivation(Finding finding)
    {
        if (_armedLeads.Count == 0 || finding.DerivedFromFindingId is not null) return;

        foreach (var lead in _armedLeads)
        {
            if (CurrentPhase <= lead.SourcePhase) continue;
            if (lead.SourceFindingId == finding.Id) continue;
            if (Mentions(finding.Target, lead.Indicator) ||
                Mentions(finding.FixParam, lead.Indicator))
            {
                finding.DerivedFromFindingId = lead.SourceFindingId;
                return;
            }
        }
    }

    private static bool Mentions(string? haystack, string indicator) =>
        !string.IsNullOrEmpty(haystack) && indicator.Length > 0 &&
        haystack.Contains(indicator, StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<Finding> Findings =>
        _findings.Values.OrderByDescending(f => f.Severity).ThenBy(f => f.Group).ThenBy(f => f.Target).ToList();

    public IReadOnlyList<CheckStatus> Checks => _checks.ToList();

    public IReadOnlyList<PhaseTiming> PhaseTimings => _phaseTimings.OrderBy(t => t.Phase).ToList();
}
