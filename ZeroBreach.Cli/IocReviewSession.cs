using ZeroBreach.Core.Model;
using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Cli;

/// <summary>
/// Per-indicator confirmation for IOCs extracted from free-form text (spec §6.6): every
/// candidate is shown with the source line it came from and any caution, and enters the
/// signature database only on an individual "y" — there is deliberately no "yes to all".
/// Confirmed indicators are detection-only: they land in the custom.* sets at POSSIBLE
/// severity, so a hit reports a finding but never arms a destructive action by itself.
/// </summary>
public sealed class IocReviewSession
{
    private readonly IReadOnlyList<ExtractedIoc> _candidates;
    private readonly SignatureDb _signatures;
    private readonly string _sourceName;

    public IocReviewSession(IReadOnlyList<ExtractedIoc> candidates, SignatureDb signatures, string sourceName)
    {
        _candidates = candidates;
        _signatures = signatures;
        _sourceName = sourceName;
    }

    /// <summary>Runs the review conversation. Returns (armed, declined) counts.</summary>
    public (int Armed, int Declined) Run()
    {
        if (_candidates.Count == 0)
        {
            Console.WriteLine($"--extract-iocs: no indicator candidates found in {_sourceName}.");
            return (0, 0);
        }

        Console.WriteLine();
        Console.WriteLine($"=== IOC review — {_candidates.Count} candidate(s) extracted from {_sourceName} ===");
        Console.WriteLine("Text-extracted indicators are low-precision (spec §6.6). Each one you confirm");
        Console.WriteLine("is armed for THIS scan only, detection-only (POSSIBLE severity, no fix action).");
        Console.WriteLine("Answer y to arm, anything else to decline, 'stop' to decline all remaining.");

        var armed = 0;
        var declined = 0;
        for (var n = 0; n < _candidates.Count; n++)
        {
            var c = _candidates[n];
            Console.WriteLine();
            Console.WriteLine($"  [{n + 1}/{_candidates.Count}] {KindLabel(c.Kind),-8} {c.Value}");
            Console.WriteLine($"        from: {c.SourceLine}");
            if (c.Caution is not null)
                Console.WriteLine($"        caution: {c.Caution}");
            Console.Write("        arm this indicator? [y/N/stop] > ");

            var input = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (input == "stop")
            {
                declined += _candidates.Count - n;
                break;
            }
            if (input == "y")
            {
                Arm(c);
                armed++;
            }
            else
            {
                declined++;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"IOC review done: {armed} armed for this scan, {declined} declined.");
        return (armed, declined);
    }

    private void Arm(ExtractedIoc ioc)
    {
        var set = ioc.Kind switch
        {
            IocKind.Sha256 => "custom.hashes",
            IocKind.Ipv4 => "custom.ips",
            IocKind.Domain => "custom.domains",
            _ => "custom.filenames",
        };
        _signatures.Add(set, new IndicatorEntry
        {
            Pattern = ioc.Value,
            Kind = ioc.Kind == IocKind.Sha256 ? MatchKind.Sha256 : MatchKind.Literal,
            Severity = Severity.Possible,
            Note = $"operator-confirmed IOC extracted from {_sourceName}",
        });
    }

    private static string KindLabel(IocKind kind) => kind switch
    {
        IocKind.Sha256 => "sha256",
        IocKind.Ipv4 => "ip",
        IocKind.Domain => "domain",
        _ => "filename",
    };
}
