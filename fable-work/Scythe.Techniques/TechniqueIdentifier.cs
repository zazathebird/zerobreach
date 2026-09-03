namespace Scythe.Techniques;

/// <summary>
/// A validated technique identifier: <c>T</c> followed by exactly four ASCII digits, optionally
/// followed by a dot and exactly three ASCII digits for a sub-technique.
/// </summary>
/// <remarks>
/// Parsing is deliberately strict (reference/07.4_technique_map.md): no trimming, no case
/// folding, no tolerance for a missing leading zero, and only the ten ASCII digits count as
/// digits. A near-miss that loaded leniently would then fail to match the same identifier
/// written correctly elsewhere, which is a silent hole in the census.
/// </remarks>
public readonly record struct TechniqueIdentifier
{
    private TechniqueIdentifier(string value, bool isSubTechnique)
    {
        Value = value;
        IsSubTechnique = isSubTechnique;
    }

    /// <summary>The identifier exactly as written, e.g. <c>T1234</c> or <c>T1234.001</c>.</summary>
    public string Value { get; }

    public bool IsSubTechnique { get; }

    /// <summary>
    /// For a sub-technique, the parent's identifier (<c>T1234</c> for <c>T1234.001</c>). For a
    /// technique, the identifier itself.
    /// </summary>
    public string ParentValue => IsSubTechnique ? Value[..TechniqueLength] : Value;

    public const int TechniqueLength = 5;

    public const int SubTechniqueLength = 9;

    /// <summary>
    /// Parses strictly. On failure <paramref name="problem"/> says which rule the text broke,
    /// phrased for a person with the file in front of them.
    /// </summary>
    public static bool TryParse(string? text, out TechniqueIdentifier identifier, out string problem)
    {
        identifier = default;

        if (text is null)
        {
            problem = "is absent";
            return false;
        }

        if (text.Length == 0)
        {
            problem = "'' is empty";
            return false;
        }

        if (text.Length != TechniqueLength && text.Length != SubTechniqueLength)
        {
            problem = LengthProblem(text);
            return false;
        }

        if (text[0] != 'T')
        {
            problem = text[0] == 't'
                ? $"'{text}' uses a lower-case 't'; identifiers are case-sensitive and start with 'T'"
                : $"'{text}' does not start with 'T'";
            return false;
        }

        for (var i = 1; i < TechniqueLength; i++)
        {
            if (!IsAsciiDigit(text[i]))
            {
                problem = $"'{text}' has a non-digit character at position {i}";
                return false;
            }
        }

        if (text.Length == TechniqueLength)
        {
            identifier = new TechniqueIdentifier(text, isSubTechnique: false);
            problem = string.Empty;
            return true;
        }

        if (text[TechniqueLength] != '.')
        {
            problem = $"'{text}' has '{text[TechniqueLength]}' where the sub-technique dot should be";
            return false;
        }

        for (var i = TechniqueLength + 1; i < SubTechniqueLength; i++)
        {
            if (!IsAsciiDigit(text[i]))
            {
                problem = $"'{text}' has a non-digit character at position {i}";
                return false;
            }
        }

        identifier = new TechniqueIdentifier(text, isSubTechnique: true);
        problem = string.Empty;
        return true;
    }

    private static string LengthProblem(string text)
    {
        // Surrounding whitespace is the near-miss most likely to come from a hand-edited file,
        // and "wrong length" would send the reader looking for a missing digit. Name it.
        if (text.Length != text.Trim().Length)
        {
            return $"'{text}' has surrounding whitespace; identifiers are not trimmed";
        }

        if (text.Length > 1 && text[0] == 'T' && text.Length < TechniqueLength)
        {
            return $"'{text}' is too short; a technique is 'T' followed by exactly four digits (missing leading zero?)";
        }

        return $"'{text}' is {text.Length} characters; a technique is 'T' plus four digits and a sub-technique adds '.' plus three digits";
    }

    // char.IsDigit accepts every Unicode decimal digit; the format is ASCII only.
    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';

    public override string ToString() => Value;
}
