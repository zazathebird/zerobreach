using System.Buffers.Binary;

namespace Scythe.Time.Tests.Fixtures;

/// <summary>
/// Constructs each encoding from a moment, rather than checking in encoded blobs.
/// </summary>
/// <remarks>
/// The epochs here are written out independently of the constants in <c>TimeDecoder</c>. That is
/// the point: a fixture that reused the library's own epoch would agree with it however wrong it
/// was, and the epoch is exactly the thing a later refactor can quietly move.
/// </remarks>
internal static class TimeFixtures
{
    internal static readonly DateTime Epoch1601 = new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    internal static readonly DateTime Epoch1970 = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    internal static readonly DateTime Epoch1899 = new(1899, 12, 30, 0, 0, 0, DateTimeKind.Unspecified);

    /// <summary>An ordinary current-decade instant, used across the suite so values line up.</summary>
    internal static readonly DateTime Ordinary =
        new(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc);

    // ------------------------------------------------------------------ 1601-epoch counters

    internal static ulong Counter1601(DateTime utc) =>
        checked((ulong)(utc.Ticks - Epoch1601.Ticks));

    internal static (uint Low, uint High) SplitCounter1601(DateTime utc)
    {
        var count = Counter1601(utc);
        return ((uint)(count & 0xFFFFFFFF), (uint)(count >> 32));
    }

    internal static byte[] Counter1601Bytes(DateTime utc)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, Counter1601(utc));
        return bytes;
    }

    // ------------------------------------------------------------------ 1970-epoch counters

    internal static long UnixSeconds(DateTime utc) =>
        (utc.Ticks - Epoch1970.Ticks) / TimeSpan.TicksPerSecond;

    internal static uint UnixSeconds32(DateTime utc) =>
        unchecked((uint)UnixSeconds(utc));

    // ------------------------------------------------------------------ packed date and time

    /// <summary>
    /// Packs a moment into the date and time words. Seconds are halved by the encoding, so an odd
    /// second cannot be expressed and is rejected here rather than silently rounded — a fixture
    /// that quietly changed the value it was asked for would make every assertion built on it a
    /// statement about something else.
    /// </summary>
    internal static (ushort Date, ushort Time) PackedDateAndTime(
        int year, int month, int day, int hour, int minute, int second)
    {
        if (second % 2 != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(second), second, "The packed time word cannot express an odd second.");
        }

        return (PackDate(year, month, day), PackTime(hour, minute, second));
    }

    /// <summary>Packs the date word from raw field values, including ones the format forbids.</summary>
    internal static ushort PackDateFields(int yearMinus1980, int month, int day) =>
        (ushort)(((yearMinus1980 & 0x7F) << 9) | ((month & 0x0F) << 5) | (day & 0x1F));

    /// <summary>Packs the time word from raw field values, including ones the format forbids.</summary>
    internal static ushort PackTimeFields(int hour, int minute, int doubleSeconds) =>
        (ushort)(((hour & 0x1F) << 11) | ((minute & 0x3F) << 5) | (doubleSeconds & 0x1F));

    internal static ushort PackDate(int year, int month, int day) =>
        PackDateFields(year - 1980, month, day);

    internal static ushort PackTime(int hour, int minute, int second) =>
        PackTimeFields(hour, minute, second / 2);

    internal static byte[] PackedDateAndTimeBytes(ushort date, ushort time)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0, 2), date);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2, 2), time);
        return bytes;
    }

    // ------------------------------------------------------------------ variant day count

    /// <summary>
    /// Builds the variant encoding of a moment: a signed whole-day offset, plus the time of day
    /// as a magnitude. Note the sign handling — for a pre-epoch moment the day part goes negative
    /// while the fraction stays positive, which is the whole reason a naive AddDays is wrong.
    /// </summary>
    internal static double VariantDayCount(DateTime local)
    {
        var delta = local - Epoch1899;
        var wholeDays = (long)Math.Floor(delta.TotalDays);
        var timeOfDayTicks = delta.Ticks - (wholeDays * TimeSpan.TicksPerDay);
        var fraction = (double)timeOfDayTicks / TimeSpan.TicksPerDay;

        return wholeDays < 0 ? wholeDays - fraction : wholeDays + fraction;
    }

    internal static byte[] VariantDayCountBytes(double days)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteDoubleLittleEndian(bytes, days);
        return bytes;
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Unwraps an Ok result, failing the test loudly if it is not Ok.</summary>
    internal static T Unwrap<T>(TimeResult<T> result) where T : class
    {
        if (result.State != TimeResultState.Ok)
        {
            throw new InvalidOperationException(
                $"expected Ok, got {result.State}: {result.Reason}");
        }

        return result.Value!;
    }
}
