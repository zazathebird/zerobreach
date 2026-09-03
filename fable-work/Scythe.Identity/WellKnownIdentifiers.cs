namespace Scythe.Identity;

/// <summary>
/// The static well-known table from reference/11.3 §11.3 and the lookup over it. Static data
/// only: values that are the same everywhere, or patterns over a domain-relative prefix. Nothing
/// here converts an identifier to an account name — that needs a directory, which needs a
/// machine and a network, and neither exists in this layer.
/// </summary>
public static class WellKnownIdentifiers
{
    // Two-letter abbreviations are the ones the descriptor string syntax (MS-DTYP §2.4.4.1,
    // "SID string") assigns to the values §11.3 tables. Rows §11.3 lists without an abbreviation
    // have none here; abbreviations whose value §11.3 does not table (DG, CA, SA, PA, RS, …) are
    // deliberately absent and parse as "unrecognised abbreviation" rather than as a guess.
    private static readonly WellKnownEntry[] Table =
    [
        Exact("S-1-0-0", "The null identifier", null, 0, 0),
        Exact("S-1-1-0", "All users", "WD", 1, 0),
        Exact("S-1-2-0", "Locally signed-on users", null, 2, 0),
        Exact("S-1-3-0", "Creator owner", "CO", 3, 0),
        Exact("S-1-3-1", "Creator group", "CG", 3, 1),
        Exact("S-1-5-2", "Users signed on over the network", "NU", 5, 2),
        Exact("S-1-5-4", "Users signed on interactively", "IU", 5, 4),
        Exact("S-1-5-6", "Service accounts", "SU", 5, 6),
        Exact("S-1-5-7", "Anonymous sign-on", "AN", 5, 7),
        Exact("S-1-5-9", "Enterprise domain controllers", "ED", 5, 9),
        Exact("S-1-5-11", "Authenticated users", "AU", 5, 11),
        Exact("S-1-5-18", "The local system account", "SY", 5, 18),
        Exact("S-1-5-19", "The local service account", "LS", 5, 19),
        Exact("S-1-5-20", "The network service account", "NS", 5, 20),
        Domain(IdentifierScope.MachineOrDomain, "The built-in administrator account", "LA", 500),
        Domain(IdentifierScope.MachineOrDomain, "The built-in guest account", "LG", 501),
        Domain(IdentifierScope.Domain, "Domain administrators group", "DA", 512),
        Domain(IdentifierScope.Domain, "Domain users group", "DU", 513),
        Domain(IdentifierScope.Domain, "Domain computers group", "DC", 515),
        Domain(IdentifierScope.Domain, "Domain controllers group", "DD", 516),
        Domain(IdentifierScope.Domain, "Enterprise administrators group", "EA", 519),
        Exact("S-1-5-32-544", "The local administrators group", "BA", 5, 32, 544),
        Exact("S-1-5-32-545", "The local users group", "BU", 5, 32, 545),
        Exact("S-1-5-32-546", "The local guests group", "BG", 5, 32, 546),
        Exact("S-1-5-32-551", "The backup operators group", "BO", 5, 32, 551),
        Exact("S-1-5-32-555", "The remote desktop users group", "RD", 5, 32, 555),
        Exact("S-1-5-32-562", "The distributed component users group", null, 5, 32, 562),
        Exact("S-1-5-32-580", "The remote management users group", "RM", 5, 32, 580),
        Prefix("S-1-5-80-*", "A per-service account", 5, 80),
        Prefix("S-1-5-83-*", "A virtual-machine account", 5, 83),
        Exact("S-1-15-2-1", "All application packages", "AC", 15, 2, 1),
        Exact("S-1-15-2-2", "All restricted application packages", null, 15, 2, 2),
        Exact("S-1-16-0", "Integrity level: untrusted", null, 16, 0),
        Exact("S-1-16-4096", "Integrity level: low", "LW", 16, 4096),
        Exact("S-1-16-8192", "Integrity level: medium", "ME", 16, 8192),
        Exact("S-1-16-8448", "Integrity level: medium-plus", "MP", 16, 8448),
        Exact("S-1-16-12288", "Integrity level: high", "HI", 16, 12288),
        Exact("S-1-16-16384", "Integrity level: system", "SI", 16, 16384),
        Exact("S-1-16-20480", "Integrity level: protected", null, 16, 20480),
    ];

    private static readonly Dictionary<string, WellKnownEntry> ByAbbreviation = BuildAbbreviations();

    /// <summary>Every row, in table order.</summary>
    public static IReadOnlyList<WellKnownEntry> Entries => Table;

    /// <summary>
    /// The first table row denoting <paramref name="identifier"/>, or a name built from the
    /// canonical string when none does. Table rows are mutually exclusive, so "first" is a
    /// determinism guarantee rather than a precedence rule.
    /// </summary>
    public static IdentifierName Describe(SecurityIdentifier identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        var canonical = identifier.ToCanonicalString();
        foreach (var entry in Table)
        {
            if (entry.Matches(identifier))
            {
                return new IdentifierName(identifier, canonical, entry.Name, entry.Scope, entry);
            }
        }

        return new IdentifierName(identifier, canonical, canonical, IdentifierScope.Unmatched, null);
    }

    /// <summary>The row a two-letter abbreviation denotes, or null when the table has none for it.</summary>
    public static WellKnownEntry? FromAbbreviation(string abbreviation)
    {
        ArgumentNullException.ThrowIfNull(abbreviation);
        return ByAbbreviation.TryGetValue(abbreviation, out var entry) ? entry : null;
    }

    /// <summary>Instantiates an exact row's value. Null for pattern rows, which denote no single value.</summary>
    public static SecurityIdentifier? ValueOf(WellKnownEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return entry.Kind == WellKnownPatternKind.Exact
            ? new SecurityIdentifier(SecurityIdentifier.RecognisedRevision, entry.Authority, entry.Leading)
            : null;
    }

    private static WellKnownEntry Exact(string pattern, string name, string? abbreviation, ulong authority, params uint[] subs) =>
        new(pattern, IdentifierScope.Fixed, name, abbreviation, WellKnownPatternKind.Exact, authority, subs, Array.Empty<uint>());

    private static WellKnownEntry Domain(IdentifierScope scope, string name, string? abbreviation, uint relativeIdentifier) =>
        new($"S-1-5-21-*-*-*-{relativeIdentifier}", scope, name, abbreviation, WellKnownPatternKind.DomainTriple, 5, [21], [relativeIdentifier]);

    private static WellKnownEntry Prefix(string pattern, string name, ulong authority, params uint[] subs) =>
        new(pattern, IdentifierScope.FixedPrefix, name, null, WellKnownPatternKind.AnySuffix, authority, subs, Array.Empty<uint>());

    private static Dictionary<string, WellKnownEntry> BuildAbbreviations()
    {
        var map = new Dictionary<string, WellKnownEntry>(StringComparer.Ordinal);
        foreach (var entry in Table)
        {
            if (entry.Abbreviation is not null)
            {
                map.Add(entry.Abbreviation, entry);
            }
        }

        return map;
    }
}
