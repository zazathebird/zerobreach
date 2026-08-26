namespace ZeroBreach.Rules.Yara.Matching;

// AST for YARA's regex dialect. Matching is over bytes, not characters: a "character
// class" is a set of byte values 0-255.

internal abstract record RegexNode;

internal sealed record RegexLiteral(byte Value) : RegexNode;

/// <summary>A byte class as a 256-bit set. Negation is already folded into the bitmap.</summary>
internal sealed record RegexClass(ByteSet Set) : RegexNode;

internal sealed record RegexConcat(IReadOnlyList<RegexNode> Nodes) : RegexNode;

internal sealed record RegexAlternation(IReadOnlyList<RegexNode> Branches) : RegexNode;

/// <summary>Repetition. Max null means unbounded. <paramref name="Lazy"/> repetitions
/// prefer the shortest match, which changes the reported match length.</summary>
internal sealed record RegexRepeat(RegexNode Body, int Min, int? Max, bool Lazy) : RegexNode;

internal enum RegexAssertionKind { BufferStart, BufferEnd, WordBoundary, NotWordBoundary }

internal sealed record RegexAssertion(RegexAssertionKind Kind) : RegexNode;

/// <summary>Mutable 256-bit byte set used while building classes; frozen into the AST.</summary>
internal sealed class ByteSet
{
    private readonly ulong[] _bits = new ulong[4];

    public void Add(byte b) => _bits[b >> 6] |= 1UL << (b & 63);

    public void AddRange(byte lo, byte hi)
    {
        for (int b = lo; b <= hi; b++)
        {
            Add((byte)b);
        }
    }

    public void AddSet(ByteSet other)
    {
        for (int i = 0; i < 4; i++)
        {
            _bits[i] |= other._bits[i];
        }
    }

    public void Invert()
    {
        for (int i = 0; i < 4; i++)
        {
            _bits[i] = ~_bits[i];
        }
    }

    public bool Contains(byte b) => (_bits[b >> 6] & (1UL << (b & 63))) != 0;

    public bool IsEmpty => _bits[0] == 0 && _bits[1] == 0 && _bits[2] == 0 && _bits[3] == 0;

    public int Count
    {
        get
        {
            int n = 0;
            foreach (var w in _bits)
            {
                n += System.Numerics.BitOperations.PopCount(w);
            }
            return n;
        }
    }

    public ByteSet Clone()
    {
        var c = new ByteSet();
        Array.Copy(_bits, c._bits, 4);
        return c;
    }

    /// <summary>Adds the opposite-case letter for every ASCII letter present (nocase is
    /// ASCII-only, deliberately: BLUEPRINT §4.2).</summary>
    public void AddAsciiCaseVariants()
    {
        for (byte b = (byte)'A'; b <= (byte)'Z'; b++)
        {
            if (Contains(b))
            {
                Add((byte)(b + 32));
            }
        }
        for (byte b = (byte)'a'; b <= (byte)'z'; b++)
        {
            if (Contains(b))
            {
                Add((byte)(b - 32));
            }
        }
    }

    public static ByteSet Word()
    {
        var s = new ByteSet();
        s.AddRange((byte)'a', (byte)'z');
        s.AddRange((byte)'A', (byte)'Z');
        s.AddRange((byte)'0', (byte)'9');
        s.Add((byte)'_');
        return s;
    }

    public static ByteSet Digit()
    {
        var s = new ByteSet();
        s.AddRange((byte)'0', (byte)'9');
        return s;
    }

    public static ByteSet Space()
    {
        var s = new ByteSet();
        foreach (char c in " \t\r\n\v\f")
        {
            s.Add((byte)c);
        }
        return s;
    }

    public static ByteSet All()
    {
        var s = new ByteSet();
        s.Invert();
        return s;
    }

    public static ByteSet AllExceptNewline()
    {
        var r = new ByteSet();
        for (int b = 0; b <= 255; b++)
        {
            if (b != '\n')
            {
                r.Add((byte)b);
            }
        }
        return r;
    }
}
