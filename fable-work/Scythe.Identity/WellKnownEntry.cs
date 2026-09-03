namespace Scythe.Identity;

/// <summary>How a table row matches: exactly, with an unconstrained domain triple, or by prefix.</summary>
public enum WellKnownPatternKind
{
    /// <summary>Authority and every sub-authority fixed.</summary>
    Exact,

    /// <summary>Authority, leading sub-authorities and trailing relative identifier fixed; three unconstrained sub-authorities between.</summary>
    DomainTriple,

    /// <summary>Authority and leading sub-authorities fixed; at least one further sub-authority, unconstrained.</summary>
    AnySuffix,
}

/// <summary>
/// One row of the well-known table: a value or pattern, a neutral display name, a scope, and the
/// two-letter descriptor-string abbreviation where one exists.
/// </summary>
public sealed record WellKnownEntry(
    string Pattern,
    IdentifierScope Scope,
    string Name,
    string? Abbreviation,
    WellKnownPatternKind Kind,
    ulong Authority,
    IReadOnlyList<uint> Leading,
    IReadOnlyList<uint> Trailing)
{
    /// <summary>The fixed trailing relative identifier of a <see cref="WellKnownPatternKind.DomainTriple"/> row.</summary>
    public uint? RelativeIdentifier =>
        Kind == WellKnownPatternKind.DomainTriple && Trailing.Count > 0 ? Trailing[^1] : null;

    /// <summary>Whether this row denotes <paramref name="identifier"/>. Only revision-1 values are matched.</summary>
    public bool Matches(SecurityIdentifier identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        if (!identifier.RevisionRecognised || identifier.Authority != Authority)
        {
            return false;
        }

        var subs = identifier.SubAuthorities;
        switch (Kind)
        {
            case WellKnownPatternKind.Exact:
                return subs.Count == Leading.Count && StartsWith(subs, Leading);

            case WellKnownPatternKind.DomainTriple:
                if (subs.Count != Leading.Count + 3 + Trailing.Count || !StartsWith(subs, Leading))
                {
                    return false;
                }

                for (var i = 0; i < Trailing.Count; i++)
                {
                    if (subs[Leading.Count + 3 + i] != Trailing[i])
                    {
                        return false;
                    }
                }

                return true;

            case WellKnownPatternKind.AnySuffix:
                return subs.Count > Leading.Count && StartsWith(subs, Leading);

            default:
                return false;
        }
    }

    private static bool StartsWith(IReadOnlyList<uint> subs, IReadOnlyList<uint> leading)
    {
        for (var i = 0; i < leading.Count; i++)
        {
            if (subs[i] != leading[i])
            {
                return false;
            }
        }

        return true;
    }
}
