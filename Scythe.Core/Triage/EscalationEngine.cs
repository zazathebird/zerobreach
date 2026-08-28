using Scythe.Core.Model;
using Scythe.Core.Signatures;

namespace Scythe.Core.Triage;

/// <summary>One indicator derived mid-scan from a finding already raised — the full
/// provenance record (what was armed, which finding surfaced it, in which phase, at what
/// severity), so the operator can audit every scope-widening decision after the run and
/// <see cref="FollowUpPlan"/> can turn the run's leads into a deeper follow-up pass.</summary>
public sealed record Lead(string Indicator, IocKind Kind,
    string SourceFindingId, int SourcePhase, Severity SourceSeverity);

/// <summary>In-run detection escalation (runs BETWEEN phases, single-threaded — the only
/// safe point to mutate SignatureDb). Derives indicator candidates from findings already
/// raised (via <see cref="IocExtractor"/> over Target/FixParam) and arms them DETECTION-ONLY
/// into the custom.* sets: Possible severity, no fix action, never destructive. Escalation
/// widens what later phases look at; it has no path into the §6 remediation model — the
/// same discipline spec §6.6 imposes on text-extracted IOCs applies here, and unlike
/// remediation (which always needs typed operator confirmation), widening detection scope
/// with low-precision POSSIBLE indicators is safe to do automatically.</summary>
public sealed class EscalationEngine
{
    private readonly SignatureDb _signatures;
    private readonly int _maxArmed;
    private readonly HashSet<string> _seenFindingIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> _leadKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Lead> _leads = new();
    private bool _capDisclosed;

    public EscalationEngine(SignatureDb signatures, int maxArmed = 200)
    {
        _signatures = signatures;
        _maxArmed = maxArmed;
    }

    /// <summary>One console-note callback per phase that armed something (or first hit the
    /// cap) — escalation changes what the rest of the run looks for, so it must never be
    /// invisible to the operator watching the scan.</summary>
    public Action<string>? OnEscalation { get; set; }

    /// <summary>Every indicator armed this run, with full provenance.</summary>
    public IReadOnlyList<Lead> Leads => _leads;

    /// <summary>True once the <c>maxArmed</c> cap blocked a candidate. A capped escalation
    /// is disclosed (spec §6.7 spirit: the scan must never look wider than it really ran).</summary>
    public bool CapReached { get; private set; }

    /// <summary>Process findings visible after a phase. Tracks already-seen finding ids
    /// internally (FindingCollector.Findings is re-sorted on every read, so slicing the
    /// list by a remembered count is unsafe — identity, not position, decides "new").
    /// Returns how many new indicators were armed.</summary>
    public int ProcessNewFindings(int phase, IReadOnlyList<Finding> allFindings)
    {
        var armed = 0;
        var capBlocked = false;

        foreach (var finding in allFindings)
        {
            if (capBlocked) break;
            if (!_seenFindingIds.Add(finding.Id)) continue;

            // Informational items must not widen the scan: an INFO note describes normal
            // machine state, and escalating from it would let benign artifacts steer the run.
            if (finding.Severity == Severity.Info) continue;

            var text = finding.FixParam is null
                ? finding.Target
                : finding.Target + "\n" + finding.FixParam;

            foreach (var ioc in IocExtractor.Extract(text))
            {
                var set = SetFor(ioc.Kind);

                // Feedback-loop guard: an indicator value already present in the target set
                // (case-insensitive) is skipped — and because every indicator escalation arms
                // lands in that same set, a finding raised BY an escalated indicator can only
                // re-surface values that are already armed. Escalation therefore cannot feed
                // its own output back in and snowball.
                if (_signatures.Set(set)
                    .Any(e => string.Equals(e.Pattern, ioc.Value, StringComparison.OrdinalIgnoreCase)))
                    continue;

                // Already recorded as a lead this run (belt and braces with the set check).
                if (_leadKeys.Contains(LeadKey(ioc))) continue;

                if (_leads.Count >= _maxArmed)
                {
                    CapReached = true;
                    capBlocked = true;
                    break;
                }

                // Detection-only arming: POSSIBLE severity, no fix action anywhere in the
                // entry — a hit reports a finding, nothing more (spec §6.6 discipline).
                _signatures.Add(set, new IndicatorEntry
                {
                    Pattern = ioc.Value,
                    Kind = ioc.Kind == IocKind.Sha256 ? MatchKind.Sha256 : MatchKind.Literal,
                    Severity = Severity.Possible,
                    Note = $"escalated mid-scan from finding {finding.Id} (phase {phase})",
                });
                _leadKeys.Add(LeadKey(ioc));
                _leads.Add(new Lead(ioc.Value, ioc.Kind, finding.Id, phase, finding.Severity));
                armed++;
            }
        }

        if (armed > 0 || (CapReached && !_capDisclosed))
        {
            var msg = $"adaptive scan: {armed} indicator(s) from phase {phase} findings armed " +
                      "detection-only (custom.* sets, POSSIBLE severity, no fix action) — " +
                      "later phases will look for them";
            if (CapReached && !_capDisclosed)
            {
                msg += $"; escalation cap of {_maxArmed} reached — further leads will NOT be armed this run";
                _capDisclosed = true; // cap disclosure goes out exactly once
            }
            OnEscalation?.Invoke(msg);
        }

        return armed;
    }

    private static string LeadKey(ExtractedIoc ioc) => $"{ioc.Kind}|{ioc.Value}";

    /// <summary>Same kind→set mapping as the CLI's IocReviewSession, so escalated and
    /// operator-confirmed indicators travel through identical scanner match paths.</summary>
    private static string SetFor(IocKind kind) => kind switch
    {
        IocKind.Sha256 => "custom.hashes",
        IocKind.Ipv4 => "custom.ips",
        IocKind.Domain => "custom.domains",
        _ => "custom.filenames",
    };
}
