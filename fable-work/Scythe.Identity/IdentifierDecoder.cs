namespace Scythe.Identity;

/// <summary>
/// The identifier's binary layout (reference/11.3 §11.3) and its string form, in both directions.
/// </summary>
public static class IdentifierDecoder
{
    /// <summary>
    /// Decodes an identifier from the start of <paramref name="bytes"/>. Surplus bytes after the
    /// identifier are ignored; <see cref="SecurityIdentifier.BinaryLength"/> says how many were used.
    /// </summary>
    public static IdentityResult<SecurityIdentifier> Decode(ReadOnlySpan<byte> bytes, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;
        if (bytes.Length > budget.MaxInputBytes)
        {
            return IdentityResult<SecurityIdentifier>.Incomplete(
                null,
                $"input is {bytes.Length} bytes; budget allows {budget.MaxInputBytes}");
        }

        return DecodeUnbudgeted(bytes);
    }

    /// <summary>The layout walk without the budget check, for the descriptor decoder, which has already budgeted the whole buffer.</summary>
    internal static IdentityResult<SecurityIdentifier> DecodeUnbudgeted(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < SecurityIdentifier.HeaderLength)
        {
            return IdentityResult<SecurityIdentifier>.Failed(
                $"identifier header needs {SecurityIdentifier.HeaderLength} bytes, buffer has {bytes.Length}",
                0);
        }

        var revision = bytes[0];
        var count = bytes[1];
        if (count > SecurityIdentifier.MaxSubAuthorityCount)
        {
            return IdentityResult<SecurityIdentifier>.Failed(
                $"sub-authority count {count} exceeds the bound of {SecurityIdentifier.MaxSubAuthorityCount}",
                1);
        }

        var needed = SecurityIdentifier.HeaderLength + 4 * count;
        if (bytes.Length < needed)
        {
            return IdentityResult<SecurityIdentifier>.Failed(
                $"sub-authority count {count} needs {needed} bytes, buffer has {bytes.Length}",
                1);
        }

        // Big-endian. The one such field in the package; see §11.3 for why this matters.
        ByteReader.TryAuthorityBigEndian48(bytes, 2, out var authority);

        var subs = new uint[count];
        for (var i = 0; i < count; i++)
        {
            ByteReader.TryU32(bytes, SecurityIdentifier.HeaderLength + 4 * i, out subs[i]);
        }

        var identifier = new SecurityIdentifier(revision, authority, subs);
        if (revision != SecurityIdentifier.RecognisedRevision)
        {
            // The layout is only known for revision 1. The bytes decoded cleanly under that
            // layout, so the value is carried as a partial — but a reader that called this Ok
            // would be asserting a layout it does not know.
            return IdentityResult<SecurityIdentifier>.Incomplete(
                identifier,
                $"unrecognised identifier revision {revision}; only revision {SecurityIdentifier.RecognisedRevision} has a known layout");
        }

        return IdentityResult<SecurityIdentifier>.Ok(identifier);
    }

    /// <summary>
    /// Parses the string form — canonical, non-canonical, or a two-letter descriptor-string
    /// abbreviation — and says which it was. Domain-relative abbreviations are
    /// <see cref="IdentityResultState.Incomplete"/> with the relative identifier known and the
    /// domain prefix stated as unavailable.
    /// </summary>
    public static IdentityResult<IdentifierParse> Parse(string text, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        budget ??= ScanBudget.Default;
        if (text.Length > budget.MaxInputBytes)
        {
            return IdentityResult<IdentifierParse>.Incomplete(
                null,
                $"input is {text.Length} characters; budget allows {budget.MaxInputBytes}");
        }

        if (text.Length == 2 && IsUpperLetter(text[0]) && IsUpperLetter(text[1]))
        {
            return ParseAbbreviation(text);
        }

        if (text.Length < 2 || (text[0] != 'S' && text[0] != 's') || text[1] != '-')
        {
            return IdentityResult<IdentifierParse>.Failed(
                "expected 'S-' prefix or a two-letter abbreviation",
                0);
        }

        var deviations = new List<string>();
        if (text[0] == 's')
        {
            deviations.Add("lower-case 's' prefix");
        }

        // Split on '-' ourselves so every failure carries a character position.
        var parts = new List<(int Start, string Text)>();
        var cursor = 2;
        while (true)
        {
            var dash = text.IndexOf('-', cursor);
            if (dash < 0)
            {
                parts.Add((cursor, text[cursor..]));
                break;
            }

            parts.Add((cursor, text[cursor..dash]));
            cursor = dash + 1;
        }

        if (parts.Count < 2)
        {
            return IdentityResult<IdentifierParse>.Failed("expected revision and authority after 'S-'", 2);
        }

        if (parts.Count - 2 > SecurityIdentifier.MaxSubAuthorityCount)
        {
            return IdentityResult<IdentifierParse>.Failed(
                $"sub-authority count {parts.Count - 2} exceeds the bound of {SecurityIdentifier.MaxSubAuthorityCount}",
                parts[2 + SecurityIdentifier.MaxSubAuthorityCount].Start);
        }

        // Revision.
        if (!TryDecimal(parts[0].Text, byte.MaxValue, out var revisionValue, out var revisionZeros))
        {
            return IdentityResult<IdentifierParse>.Failed("revision is not a decimal number in 0–255", parts[0].Start);
        }

        if (revisionZeros)
        {
            deviations.Add("leading zero in revision");
        }

        // Authority: decimal, or 0x plus up to twelve hexadecimal digits.
        var authorityText = parts[1].Text;
        ulong authority;
        if (authorityText.Length >= 2 && authorityText[0] == '0' && (authorityText[1] == 'x' || authorityText[1] == 'X'))
        {
            var digits = authorityText[2..];
            if (!TryHex(digits, out authority, out var lowerCase))
            {
                return IdentityResult<IdentifierParse>.Failed(
                    "authority is not 0x followed by one to twelve hexadecimal digits",
                    parts[1].Start);
            }

            if (authority <= SecurityIdentifier.LargestDecimalAuthority)
            {
                deviations.Add("authority written in hexadecimal but fits in 32 bits");
            }
            else
            {
                if (digits.Length != 12)
                {
                    deviations.Add($"hexadecimal authority has {digits.Length} digits, canonical is 12");
                }

                if (authorityText[1] == 'X')
                {
                    deviations.Add("upper-case 'X' in authority prefix");
                }

                if (lowerCase)
                {
                    deviations.Add("lower-case hexadecimal digits in authority");
                }
            }
        }
        else
        {
            if (!TryDecimal(authorityText, SecurityIdentifier.MaxAuthority, out authority, out var authorityZeros))
            {
                return IdentityResult<IdentifierParse>.Failed(
                    "authority is not a decimal number within 48 bits",
                    parts[1].Start);
            }

            if (authorityZeros)
            {
                deviations.Add("leading zero in authority");
            }

            if (authority > SecurityIdentifier.LargestDecimalAuthority)
            {
                deviations.Add("authority written in decimal but does not fit in 32 bits");
            }
        }

        var subs = new uint[parts.Count - 2];
        for (var i = 0; i < subs.Length; i++)
        {
            var part = parts[2 + i];
            if (!TryDecimal(part.Text, uint.MaxValue, out var sub, out var subZeros))
            {
                return IdentityResult<IdentifierParse>.Failed(
                    $"sub-authority {i} is not a decimal number within 32 bits",
                    part.Start);
            }

            if (subZeros)
            {
                deviations.Add($"leading zero in sub-authority {i}");
            }

            subs[i] = (uint)sub;
        }

        var identifier = new SecurityIdentifier((byte)revisionValue, authority, subs);
        var deviation = deviations.Count == 0 ? null : string.Join("; ", deviations);
        var parse = new IdentifierParse(
            identifier,
            deviation is null ? IdentifierStringForm.Canonical : IdentifierStringForm.NonCanonical,
            WasCanonical: deviation is null,
            deviation,
            Abbreviation: null,
            RelativeIdentifier: identifier.RelativeIdentifier);

        if (!identifier.RevisionRecognised)
        {
            return IdentityResult<IdentifierParse>.Incomplete(
                parse,
                $"unrecognised identifier revision {identifier.Revision}; only revision {SecurityIdentifier.RecognisedRevision} has a known layout");
        }

        return IdentityResult<IdentifierParse>.Ok(parse);
    }

    private static IdentityResult<IdentifierParse> ParseAbbreviation(string text)
    {
        var entry = WellKnownIdentifiers.FromAbbreviation(text);
        if (entry is null)
        {
            // Might be a real abbreviation the table does not carry, so this is "unsupported",
            // not "malformed".
            return IdentityResult<IdentifierParse>.Incomplete(
                null,
                $"unrecognised abbreviation '{text}'; the well-known table has no row for it");
        }

        var value = WellKnownIdentifiers.ValueOf(entry);
        if (value is not null)
        {
            return IdentityResult<IdentifierParse>.Ok(new IdentifierParse(
                value,
                IdentifierStringForm.WellKnownAbbreviation,
                WasCanonical: false,
                Deviation: $"abbreviation '{text}' for {entry.Pattern}",
                Abbreviation: text,
                RelativeIdentifier: value.RelativeIdentifier));
        }

        // Domain-relative: the trailing relative identifier is known, the domain prefix is not
        // in the string, and inventing one would be a guess dressed as an answer.
        return IdentityResult<IdentifierParse>.Incomplete(
            new IdentifierParse(
                Identifier: null,
                IdentifierStringForm.DomainRelativeAbbreviation,
                WasCanonical: false,
                Deviation: $"abbreviation '{text}' for {entry.Pattern}",
                Abbreviation: text,
                RelativeIdentifier: entry.RelativeIdentifier),
            $"domain prefix unavailable: '{text}' denotes {entry.Pattern}, relative to a domain the string does not contain");
    }

    private static bool IsUpperLetter(char c) => c >= 'A' && c <= 'Z';

    private static bool TryDecimal(string text, ulong max, out ulong value, out bool leadingZero)
    {
        value = 0;
        leadingZero = text.Length > 1 && text[0] == '0';
        if (text.Length == 0)
        {
            return false;
        }

        foreach (var c in text)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }

            var digit = (ulong)(c - '0');
            if (value > (max - digit) / 10)
            {
                return false;
            }

            value = value * 10 + digit;
        }

        return true;
    }

    private static bool TryHex(string digits, out ulong value, out bool lowerCase)
    {
        value = 0;
        lowerCase = false;
        if (digits.Length is 0 or > 12)
        {
            return false;
        }

        foreach (var c in digits)
        {
            int nibble;
            if (c >= '0' && c <= '9')
            {
                nibble = c - '0';
            }
            else if (c >= 'A' && c <= 'F')
            {
                nibble = c - 'A' + 10;
            }
            else if (c >= 'a' && c <= 'f')
            {
                nibble = c - 'a' + 10;
                lowerCase = true;
            }
            else
            {
                return false;
            }

            value = (value << 4) | (uint)nibble;
        }

        return true;
    }
}
