namespace Scythe.Text;

/// <summary>
/// One linear pass over the buffer gathering everything detection needs: UTF-8 structural
/// validity, whether any multi-byte sequence appeared, and the byte statistics the UTF-16
/// heuristic and the confidence caps read.
/// </summary>
internal readonly record struct BufferScan(
    bool IsValidUtf8,
    int MultiByteSequenceCount,
    int NulAtEvenOffset,
    int NulAtOddOffset,
    int ControlByteCount)
{
    internal int NulByteCount => NulAtEvenOffset + NulAtOddOffset;

    /// <summary>
    /// Validates UTF-8 structurally against the byte-range table in reference/11.2_text.md —
    /// over-long forms, surrogate halves and code points above the maximum are rejected by the
    /// second-byte range, never by decoding and inspecting afterwards.
    /// </summary>
    internal static BufferScan Run(ReadOnlySpan<byte> bytes)
    {
        var valid = true;
        var multiByte = 0;
        var nulEven = 0;
        var nulOdd = 0;
        var controls = 0;
        var i = 0;

        for (var j = 0; j < bytes.Length; j++)
        {
            var b = bytes[j];
            if (b == 0x00)
            {
                if ((j & 1) == 0)
                {
                    nulEven++;
                }
                else
                {
                    nulOdd++;
                }
            }
            else if ((b < 0x20 && b is not (0x09 or 0x0A or 0x0D)) || b == 0x7F)
            {
                controls++;
            }
        }

        while (i < bytes.Length)
        {
            var consumed = Utf8Sequence.Measure(bytes[i..]);
            if (consumed < 0)
            {
                valid = false;
                i++;
            }
            else
            {
                if (consumed > 1)
                {
                    multiByte++;
                }

                i += consumed;
            }
        }

        return new BufferScan(valid, multiByte, nulEven, nulOdd, controls);
    }
}

/// <summary>
/// The UTF-8 byte-range rules from reference/11.2_text.md, shared by the validator and the
/// decoder so the two cannot disagree about what is well-formed.
/// </summary>
internal static class Utf8Sequence
{
    /// <summary>
    /// Length of the well-formed sequence starting at the head of the span, or -1 when the head
    /// byte does not begin one — including a truncated tail at end of buffer, which is not a
    /// well-formed sequence of the bytes that are actually present.
    /// </summary>
    internal static int Measure(ReadOnlySpan<byte> bytes)
    {
        var lead = bytes[0];

        if (lead <= 0x7F)
        {
            return 1;
        }

        // The bolded second-byte ranges in the reference table are the whole point: a validator
        // built from "lead says N continuations, check they are 80–BF" accepts over-long forms,
        // surrogate halves and out-of-range code points.
        int length;
        byte secondLow;
        byte secondHigh;
        switch (lead)
        {
            case >= 0xC2 and <= 0xDF:
                length = 2;
                secondLow = 0x80;
                secondHigh = 0xBF;
                break;
            case 0xE0:
                length = 3;
                secondLow = 0xA0; // below A0 is an over-long three-byte form
                secondHigh = 0xBF;
                break;
            case >= 0xE1 and <= 0xEC:
            case 0xEE or 0xEF:
                length = 3;
                secondLow = 0x80;
                secondHigh = 0xBF;
                break;
            case 0xED:
                length = 3;
                secondLow = 0x80;
                secondHigh = 0x9F; // A0–BF would encode a surrogate half
                break;
            case 0xF0:
                length = 4;
                secondLow = 0x90; // below 90 is an over-long four-byte form
                secondHigh = 0xBF;
                break;
            case >= 0xF1 and <= 0xF3:
                length = 4;
                secondLow = 0x80;
                secondHigh = 0xBF;
                break;
            case 0xF4:
                length = 4;
                secondLow = 0x80;
                secondHigh = 0x8F; // 90+ is above U+10FFFF
                break;
            default: // C0, C1, F5–FF, or a continuation byte with no lead
                return -1;
        }

        if (bytes.Length < length)
        {
            return -1;
        }

        if (bytes[1] < secondLow || bytes[1] > secondHigh)
        {
            return -1;
        }

        for (var k = 2; k < length; k++)
        {
            if (bytes[k] < 0x80 || bytes[k] > 0xBF)
            {
                return -1;
            }
        }

        return length;
    }
}
