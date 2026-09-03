namespace Scythe.Identity;

/// <summary>
/// An identifier with whatever the static table can say about it. An unmatched identifier is a
/// complete, correct answer: <see cref="DisplayName"/> is then the canonical string and
/// <see cref="Scope"/> is <see cref="IdentifierScope.Unmatched"/>.
/// </summary>
public sealed record IdentifierName(
    SecurityIdentifier Identifier,
    string Canonical,
    string DisplayName,
    IdentifierScope Scope,
    WellKnownEntry? Entry);
