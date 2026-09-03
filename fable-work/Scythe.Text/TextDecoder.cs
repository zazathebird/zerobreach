using System.Text;

namespace Scythe.Text;

/// <summary>
/// Decodes a byte buffer in a named encoding. Two entry points, and the difference between them
/// is the whole safety story (Q2 brief): <see cref="DecodeStrict"/> refuses the moment any byte
/// cannot be decoded; <see cref="DecodeReporting"/> substitutes one U+FFFD per undecodable run
/// and records every run in both byte and character coordinates.
/// </summary>
public static class TextDecoder
{
    private const char Replacement = '�';

    /// <summary>
    /// Returns Incomplete with a reason the moment any byte cannot be decoded, and no text.
    /// Use where a wrong string is worse than no string. The partial value carries the original
    /// bytes so a caller can still hash or store what it was given.
    /// </summary>
    public static TextResult<DecodedText> DecodeStrict(
        byte[] bytes,
        TextEncodingKind encoding,
        ScanBudget? budget = null)
        => Decode(bytes, encoding, strict: true, budget ?? ScanBudget.Default);

    /// <summary>
    /// Returns Ok with text plus <see cref="DecodedText.UndecodableRuns"/>. Every U+FFFD in the
    /// text not covered by a run entry was present in the source;
    /// <see cref="DecodedText.SourceReplacementCharacterCount"/> counts exactly those.
    /// </summary>
    public static TextResult<DecodedText> DecodeReporting(
        byte[] bytes,
        TextEncodingKind encoding,
        ScanBudget? budget = null)
        => Decode(bytes, encoding, strict: false, budget ?? ScanBudget.Default);

    private static TextResult<DecodedText> Decode(
        byte[] bytes,
        TextEncodingKind encoding,
        bool strict,
        ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        if (bytes.LongLength > budget.MaxInputBytes)
        {
            return TextResult<DecodedText>.Incomplete(
                Empty(encoding, bytes),
                $"input is {bytes.LongLength} bytes, over the {budget.MaxInputBytes}-byte MaxInputBytes budget; decode did not run");
        }

        switch (encoding)
        {
            case TextEncodingKind.Ascii:
                return new Decoder(bytes, encoding, 0, strict, budget.MaxMatches).DecodeAscii();
            case TextEncodingKind.Utf8:
                return new Decoder(bytes, encoding, MatchedMarkLength(bytes, encoding), strict, budget.MaxMatches).DecodeUtf8();
            case TextEncodingKind.Utf16LittleEndian:
            case TextEncodingKind.Utf16BigEndian:
                return new Decoder(bytes, encoding, MatchedMarkLength(bytes, encoding), strict, budget.MaxMatches)
                    .DecodeUtf16(bigEndian: encoding == TextEncodingKind.Utf16BigEndian);
            case TextEncodingKind.Utf32LittleEndian:
            case TextEncodingKind.Utf32BigEndian:
                return new Decoder(bytes, encoding, MatchedMarkLength(bytes, encoding), strict, budget.MaxMatches)
                    .DecodeUtf32(bigEndian: encoding == TextEncodingKind.Utf32BigEndian);
            case TextEncodingKind.Utf7:
            case TextEncodingKind.Utf1:
            case TextEncodingKind.UtfEbcdic:
            case TextEncodingKind.Scsu:
            case TextEncodingKind.Bocu1:
            case TextEncodingKind.Gb18030:
                // Named but not decoded (reference/11.2_text.md): naming an encoding this
                // library will not decode beats either silence or a wrong string.
                return TextResult<DecodedText>.Incomplete(
                    Empty(encoding, bytes),
                    $"{encoding} recognised but not decoded");
            default:
                var page = CodePage.ForKind(encoding);
                if (page is not null)
                {
                    return new Decoder(bytes, encoding, 0, strict, budget.MaxMatches).DecodeSingleByte(page);
                }

                return TextResult<DecodedText>.Failed($"unrecognised encoding kind {encoding}");
        }
    }

    private static int MatchedMarkLength(ReadOnlySpan<byte> bytes, TextEncodingKind encoding)
    {
        var mark = ByteOrderMark.MarkFor(encoding);
        return mark.Length > 0 && bytes.Length >= mark.Length && bytes[..mark.Length].SequenceEqual(mark)
            ? mark.Length
            : 0;
    }

    private static DecodedText Empty(TextEncodingKind encoding, byte[] bytes) =>
        new(string.Empty, encoding, 0, [], [], 0, bytes);

    /// <summary>
    /// The shared decode machinery: text accumulation, undecodable-run coalescing (adjacent
    /// undecodable bytes are one decoding event and one run), the MaxMatches ceiling, and the
    /// strict-mode refusal.
    /// </summary>
    private sealed class Decoder(byte[] bytes, TextEncodingKind encoding, int markLength, bool strict, int maxMatches)
    {
        private readonly StringBuilder _text = new();
        private readonly List<UndecodableRun> _runs = [];
        private readonly List<UnpairedSurrogate> _surrogates = [];
        private int _sourceReplacements;
        private int _runStart = -1;
        private int _runLength;

        private TextResult<DecodedText>? _terminal;

        internal TextResult<DecodedText> DecodeAscii()
        {
            for (var i = markLength; i < bytes.Length && _terminal is null; i++)
            {
                if (bytes[i] <= 0x7F)
                {
                    Append((char)bytes[i]);
                }
                else
                {
                    Undecodable(i, 1, $"byte 0x{bytes[i]:X2} at offset 0x{i:X}: not ASCII");
                }
            }

            return Finish();
        }

        internal TextResult<DecodedText> DecodeUtf8()
        {
            var i = markLength;
            while (i < bytes.Length && _terminal is null)
            {
                var consumed = Utf8Sequence.Measure(bytes.AsSpan(i));
                if (consumed < 0)
                {
                    Undecodable(i, 1,
                        $"byte 0x{bytes[i]:X2} at offset 0x{i:X}: not a valid UTF-8 sequence, or the sequence it starts is over-long, a surrogate half, out of range or truncated");
                    i++;
                    continue;
                }

                var codePoint = bytes[i] switch
                {
                    <= 0x7F => bytes[i],
                    <= 0xDF => ((bytes[i] & 0x1F) << 6) | (bytes[i + 1] & 0x3F),
                    <= 0xEF => ((bytes[i] & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F),
                    _ => ((bytes[i] & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12)
                         | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F),
                };
                AppendCodePoint(codePoint);
                i += consumed;
            }

            return Finish();
        }

        internal TextResult<DecodedText> DecodeUtf16(bool bigEndian)
        {
            var i = markLength;
            while (i + 1 < bytes.Length && _terminal is null)
            {
                var unit = ReadUnit(i, bigEndian);
                if (char.IsHighSurrogate(unit) && i + 3 < bytes.Length)
                {
                    var next = ReadUnit(i + 2, bigEndian);
                    if (char.IsLowSurrogate(next))
                    {
                        Append(unit);
                        Append(next);
                        i += 4;
                        continue;
                    }
                }

                if (char.IsSurrogate(unit))
                {
                    // Reported, not replaced: unpaired surrogates are legal in a .NET string
                    // and a caller may need them intact.
                    _surrogates.Add(new UnpairedSurrogate(i, _text.Length, unit));
                }

                Append(unit);
                i += 2;
            }

            if (_terminal is null && i < bytes.Length)
            {
                Undecodable(i, bytes.Length - i,
                    $"offset 0x{i:X}: one byte left over, not a whole UTF-16 code unit");
            }

            return Finish();
        }

        internal TextResult<DecodedText> DecodeUtf32(bool bigEndian)
        {
            var i = markLength;
            while (i + 3 < bytes.Length && _terminal is null)
            {
                var unit = bigEndian
                    ? (uint)((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3])
                    : (uint)((bytes[i + 3] << 24) | (bytes[i + 2] << 16) | (bytes[i + 1] << 8) | bytes[i]);

                if (unit > 0x10FFFF || (unit >= 0xD800 && unit <= 0xDFFF))
                {
                    Undecodable(i, 4,
                        $"unit 0x{unit:X8} at offset 0x{i:X}: not a Unicode scalar value");
                }
                else
                {
                    AppendCodePoint((int)unit);
                }

                i += 4;
            }

            if (_terminal is null && i < bytes.Length)
            {
                Undecodable(i, bytes.Length - i,
                    $"offset 0x{i:X}: {bytes.Length - i} byte(s) left over, not a whole UTF-32 code unit");
            }

            return Finish();
        }

        internal TextResult<DecodedText> DecodeSingleByte(CodePage page)
        {
            for (var i = markLength; i < bytes.Length && _terminal is null; i++)
            {
                var entry = page.Map[bytes[i]];
                if (entry == CodePage.UndefinedEntry)
                {
                    Undecodable(i, 1,
                        $"byte 0x{bytes[i]:X2} at offset 0x{i:X}: {page.Name} leaves this entry undefined");
                }
                else
                {
                    Append((char)entry);
                }
            }

            return Finish();
        }

        private char ReadUnit(int offset, bool bigEndian) => bigEndian
            ? (char)((bytes[offset] << 8) | bytes[offset + 1])
            : (char)((bytes[offset + 1] << 8) | bytes[offset]);

        private void AppendCodePoint(int codePoint)
        {
            if (codePoint <= 0xFFFF)
            {
                Append((char)codePoint);
            }
            else
            {
                FlushRun();
                var v = codePoint - 0x10000;
                _text.Append((char)(0xD800 | (v >> 10)));
                _text.Append((char)(0xDC00 | (v & 0x3FF)));
            }
        }

        private void Append(char c)
        {
            FlushRun();
            if (c == Replacement)
            {
                // The character was genuinely in the source. Counting it here is what lets a
                // caller tell a file-original replacement from a tool-inserted one.
                _sourceReplacements++;
            }

            _text.Append(c);
        }

        private void Undecodable(int offset, int length, string strictReason)
        {
            if (strict)
            {
                // No text: a strict caller asked for a wrong string to be worse than no string.
                // The partial value still carries the original bytes and the mark that was
                // skipped, so the caller can hash and attribute what it was given.
                _terminal = TextResult<DecodedText>.Incomplete(
                    new DecodedText(string.Empty, encoding, markLength, [], [], 0, bytes),
                    strictReason,
                    offset);
                return;
            }

            if (_runStart >= 0 && _runStart + _runLength == offset)
            {
                // Adjacent undecodable bytes are one decoding event and coalesce into one run.
                _runLength += length;
                return;
            }

            FlushRun();

            if (_runs.Count >= maxMatches)
            {
                _terminal = TextResult<DecodedText>.Incomplete(
                    Build(),
                    $"undecodable-run count reached the MaxMatches budget ({maxMatches}) at offset 0x{offset:X}; text and runs up to that offset are carried",
                    offset);
                return;
            }

            _runStart = offset;
            _runLength = length;
        }

        private void FlushRun()
        {
            if (_runStart < 0)
            {
                return;
            }

            _runs.Add(new UndecodableRun(_runStart, _runLength, _text.Length, 1));
            _text.Append(Replacement);
            _runStart = -1;
            _runLength = 0;
        }

        private TextResult<DecodedText> Finish()
        {
            if (_terminal is not null)
            {
                return _terminal;
            }

            FlushRun();
            return TextResult<DecodedText>.Ok(Build());
        }

        private DecodedText Build()
        {
            // Build() is called both at the end and when MaxMatches trips mid-run; any
            // unflushed run at that point has not been substituted and is not listed.
            return new DecodedText(
                _text.ToString(),
                encoding,
                markLength,
                _runs,
                _surrogates,
                _sourceReplacements,
                bytes);
        }
    }
}
