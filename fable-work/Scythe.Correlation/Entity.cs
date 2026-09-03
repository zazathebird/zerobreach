namespace Scythe.Correlation;

/// <summary>
/// One normalised entity: a kind and the normalised spelling. Two entities are equal when their
/// kinds match and their values compare equal under <see cref="ValueComparer"/>.
/// </summary>
/// <remarks>
/// Every kind here is case-insensitive on its platform (NTFS paths, registry keys and value names,
/// DNS names, hexadecimal address digits), so equality is one explicit ordinal case-insensitive
/// comparison for all of them. Ordinal-ignore-case is the culture-independent fold: it upper-cases
/// each UTF-16 unit by the invariant simple case mapping and compares the results, which is also
/// what the target file system does. It is deliberately not <c>ToLower()</c> — that consults the
/// thread culture and makes two runs of the library disagree depending on the machine's locale —
/// and not <c>ToLowerInvariant()</c> either, whose full case mapping merges characters the file
/// system keeps distinct (the Kelvin sign U+212A lower-cases to an ordinary <c>k</c>).
/// <para>
/// <see cref="Value"/> preserves the spelling the normaliser produced from its input (drive letter
/// and hive upper-cased, host names ASCII-lower-cased, everything else as written). When several
/// spellings of one entity occur in a run, <see cref="ChainBuilder"/> reports the ordinal-smallest.
/// </para>
/// </remarks>
public sealed class Entity : IEquatable<Entity>
{
    /// <summary>The comparison every kind's values are equal under.</summary>
    public static StringComparer ValueComparer { get; } = StringComparer.OrdinalIgnoreCase;

    /// <summary>
    /// Total order over entities: by <see cref="Kind"/> in declaration order, then by value under
    /// <see cref="ValueComparer"/>, then by value ordinally so that two spellings of one entity
    /// still order deterministically.
    /// </summary>
    public static IComparer<Entity> Ordering { get; } = new EntityOrdering();

    internal Entity(EntityKind kind, string value)
    {
        Kind = kind;
        Value = value;
    }

    public EntityKind Kind { get; }

    /// <summary>The normalised spelling.</summary>
    public string Value { get; }

    public bool Equals(Entity? other) =>
        other is not null && Kind == other.Kind && ValueComparer.Equals(Value, other.Value);

    public override bool Equals(object? obj) => obj is Entity other && Equals(other);

    public override int GetHashCode() => HashCode.Combine((int)Kind, ValueComparer.GetHashCode(Value));

    public override string ToString() => Kind + ":" + Value;

    private sealed class EntityOrdering : IComparer<Entity>
    {
        public int Compare(Entity? x, Entity? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            var byKind = ((int)x.Kind).CompareTo((int)y.Kind);
            if (byKind != 0) return byKind;
            var byFold = ValueComparer.Compare(x.Value, y.Value);
            return byFold != 0 ? byFold : string.CompareOrdinal(x.Value, y.Value);
        }
    }
}
