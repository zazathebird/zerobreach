namespace Scythe.Identity;

/// <summary>How the string handed to <see cref="IdentifierDecoder.Parse"/> was written.</summary>
public enum IdentifierStringForm
{
    /// <summary>Exactly what <see cref="SecurityIdentifier.ToCanonicalString"/> would produce.</summary>
    Canonical,

    /// <summary>
    /// Denotes the same value but re-renders differently — authority in the other radix, lower-case
    /// prefix, leading zeros. <see cref="IdentifierParse.Deviation"/> says which.
    /// </summary>
    NonCanonical,

    /// <summary>A two-letter descriptor-string abbreviation denoting a fixed well-known value.</summary>
    WellKnownAbbreviation,

    /// <summary>
    /// A two-letter abbreviation relative to a domain the string does not contain. Only the
    /// trailing relative identifier is known; there is no <see cref="IdentifierParse.Identifier"/>.
    /// </summary>
    DomainRelativeAbbreviation,
}

/// <summary>
/// What a string parse produced. <see cref="Identifier"/> is null only for the domain-relative
/// abbreviation form, where the value cannot be completed without a domain the string does not
/// carry — that case is reported as <see cref="IdentityResultState.Incomplete"/>, never resolved
/// against a guessed domain.
/// </summary>
public sealed record IdentifierParse(
    SecurityIdentifier? Identifier,
    IdentifierStringForm Form,
    bool WasCanonical,
    string? Deviation,
    string? Abbreviation,
    uint? RelativeIdentifier);
