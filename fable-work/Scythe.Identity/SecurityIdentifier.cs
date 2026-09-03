using System.Globalization;
using System.Text;

namespace Scythe.Identity;

/// <summary>
/// A decoded security identifier: revision, 48-bit identifier authority and up to fifteen
/// sub-authorities. Layout and canonical string form are in reference/11.3_identity.md §11.3.
/// </summary>
/// <remarks>
/// Immutable and value-equal. The type carries no name and no verdict — naming is
/// <see cref="WellKnownIdentifiers.Describe"/>'s job and only for the values that are the same
/// on every machine.
/// </remarks>
public sealed class SecurityIdentifier : IEquatable<SecurityIdentifier>
{
    /// <summary>The only revision whose layout this library knows.</summary>
    public const byte RecognisedRevision = 1;

    /// <summary>Upper bound on the sub-authority count, from the format.</summary>
    public const int MaxSubAuthorityCount = 15;

    /// <summary>The authority is 48 bits wide on disk.</summary>
    public const ulong MaxAuthority = (1UL << 48) - 1;

    /// <summary>Revision, count and authority: the bytes before the sub-authority array.</summary>
    public const int HeaderLength = 8;

    /// <summary>
    /// Authorities that fit in 32 bits render in decimal; larger ones as <c>0x</c> plus twelve
    /// hexadecimal digits. reference/11.3 §11.3, canonical string form.
    /// </summary>
    public const ulong LargestDecimalAuthority = uint.MaxValue;

    private readonly uint[] _subAuthorities;

    public SecurityIdentifier(byte revision, ulong authority, IReadOnlyList<uint> subAuthorities)
    {
        ArgumentNullException.ThrowIfNull(subAuthorities);
        if (authority > MaxAuthority)
        {
            throw new ArgumentOutOfRangeException(nameof(authority), authority, "authority is 48 bits wide");
        }

        if (subAuthorities.Count > MaxSubAuthorityCount)
        {
            throw new ArgumentOutOfRangeException(nameof(subAuthorities), subAuthorities.Count, "at most 15 sub-authorities");
        }

        Revision = revision;
        Authority = authority;
        _subAuthorities = subAuthorities.ToArray();
    }

    public byte Revision { get; }

    /// <summary>The 48-bit identifier authority, as a value (the on-disk field is big-endian).</summary>
    public ulong Authority { get; }

    public IReadOnlyList<uint> SubAuthorities => _subAuthorities;

    /// <summary>Bytes the binary form occupies: 8 + 4 × count.</summary>
    public int BinaryLength => HeaderLength + 4 * _subAuthorities.Length;

    /// <summary>True when <see cref="Revision"/> is the one whose layout this library knows.</summary>
    public bool RevisionRecognised => Revision == RecognisedRevision;

    /// <summary>The final sub-authority, or null when there are none. Absent is not zero.</summary>
    public uint? RelativeIdentifier =>
        _subAuthorities.Length == 0 ? null : _subAuthorities[^1];

    /// <summary>
    /// <c>S-&lt;revision&gt;-&lt;authority&gt;-&lt;sub&gt;…</c>, authority in decimal when it fits in 32
    /// bits and as <c>0x</c> plus twelve upper-case hexadecimal digits otherwise. Invariant culture.
    /// </summary>
    public string ToCanonicalString()
    {
        var text = new StringBuilder(32);
        text.Append("S-");
        text.Append(Revision.ToString(CultureInfo.InvariantCulture));
        text.Append('-');
        if (Authority <= LargestDecimalAuthority)
        {
            text.Append(Authority.ToString(CultureInfo.InvariantCulture));
        }
        else
        {
            text.Append("0x");
            text.Append(Authority.ToString("X12", CultureInfo.InvariantCulture));
        }

        foreach (var sub in _subAuthorities)
        {
            text.Append('-');
            text.Append(sub.ToString(CultureInfo.InvariantCulture));
        }

        return text.ToString();
    }

    /// <summary>The binary form, exactly as §11.3 lays it out: big-endian authority, little-endian sub-authorities.</summary>
    public byte[] ToBytes()
    {
        var bytes = new byte[BinaryLength];
        bytes[0] = Revision;
        bytes[1] = (byte)_subAuthorities.Length;
        for (var i = 0; i < 6; i++)
        {
            bytes[2 + i] = (byte)(Authority >> (8 * (5 - i)));
        }

        for (var i = 0; i < _subAuthorities.Length; i++)
        {
            var sub = _subAuthorities[i];
            var at = HeaderLength + 4 * i;
            bytes[at] = (byte)sub;
            bytes[at + 1] = (byte)(sub >> 8);
            bytes[at + 2] = (byte)(sub >> 16);
            bytes[at + 3] = (byte)(sub >> 24);
        }

        return bytes;
    }

    public override string ToString() => ToCanonicalString();

    public bool Equals(SecurityIdentifier? other) =>
        other is not null
        && Revision == other.Revision
        && Authority == other.Authority
        && _subAuthorities.AsSpan().SequenceEqual(other._subAuthorities);

    public override bool Equals(object? obj) => Equals(obj as SecurityIdentifier);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Revision);
        hash.Add(Authority);
        foreach (var sub in _subAuthorities)
        {
            hash.Add(sub);
        }

        return hash.ToHashCode();
    }
}
