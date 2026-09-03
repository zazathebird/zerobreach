using System.Globalization;
using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// Same bytes, same output — under any host culture, any host zone, and twice in a row.
/// </summary>
/// <remarks>
/// These tests mutate process-global state, which is why parallelisation is disabled for the
/// assembly in AssemblyInfo.cs. Each one restores what it changed in a finally block.
/// <para>
/// The cultures are built by cloning the invariant culture and mutating its
/// <see cref="DateTimeFormatInfo"/> rather than by naming real ones. <c>InvariantGlobalization</c>
/// is set for the whole package in Directory.Build.props, so <c>new CultureInfo("fr-FR")</c>
/// either throws or hands back something that behaves invariantly — and a culture that behaves
/// invariantly would let a missing <c>CultureInfo.InvariantCulture</c> argument sail through. A
/// mutated separator bites either way.
/// </para>
/// </remarks>
public sealed class DeterminismTests
{
    private static CultureInfo HostileCulture(string timeSeparator, string dateSeparator)
    {
        var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        culture.DateTimeFormat.TimeSeparator = timeSeparator;
        culture.DateTimeFormat.DateSeparator = dateSeparator;
        return culture;
    }

    private static IEnumerable<CultureInfo> Cultures =>
    [
        CultureInfo.InvariantCulture,
        HostileCulture("#", "!"),
        HostileCulture("·", "~"),
    ];

    private static NormalisedTimestamp[] OneOfEachEncoding()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 34, 56);
        var (low, high) = TimeFixtures.SplitCounter1601(TimeFixtures.Ordinary);

        return
        [
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(TimeFixtures.Counter1601(TimeFixtures.Ordinary))),
            TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(low, high)),
            TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601(
                TimeFixtures.Counter1601(TimeFixtures.Ordinary).ToString(CultureInfo.InvariantCulture))),
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(TimeFixtures.UnixSeconds(TimeFixtures.Ordinary))),
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(
                TimeFixtures.UnixSeconds32(TimeFixtures.Ordinary), CounterSignedness.Unsigned)),
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time)),
            TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(
                TimeFixtures.VariantDayCount(new DateTime(2021, 6, 5, 12, 34, 56, 500)))),
            TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 34, 56, 789)).Timestamp,
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0)),
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time)).WithKnownOffset(TimeSpan.FromHours(-5)),
        ];
    }

    private static string Render()
    {
        var values = OneOfEachEncoding();

        var lines = values.Select(v => string.Concat(
            TimeFormatter.Format(v), "|", v.Raw.BytesHex, "|", v.Raw.Scalar));

        // Comparison is exercised too, not just formatting: an outcome that moved with the host
        // would be just as much a determinism defect and would not show up in the rendered dates.
        var outcomes = from a in values
                       from b in values
                       select TimeComparer.Compare(a, b).ToString();

        return string.Join("\n", lines.Concat(outcomes));
    }

    [Fact]
    public void OutputIsByteIdenticalUnderEveryHostCulture()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            string? first = null;

            foreach (var culture in Cultures)
            {
                CultureInfo.CurrentCulture = culture;
                var rendered = Render();

                first ??= rendered;
                Assert.Equal(first, rendered);

                // And the separator the hostile culture would have imposed never appears.
                Assert.Contains("12:34:56", rendered, StringComparison.Ordinal);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void TheHostileCulturesWouldActuallyChangeAnUnguardedFormat()
    {
        // The negative control. Without this, the culture test above could pass because the
        // cultures are inert rather than because the library ignores them.
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = HostileCulture("#", "!");

            var unguarded = TimeFixtures.Ordinary.ToString("yyyy-MM-ddTHH:mm:ss");

            Assert.Equal("2021-06-05T12#34#56", unguarded);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void OutputIsByteIdenticalUnderDifferentHostTimeZones()
    {
        var original = Environment.GetEnvironmentVariable("TZ");
        try
        {
            var newYork = RenderUnderZone("America/New_York", out var newYorkOffset);
            var tokyo = RenderUnderZone("Asia/Tokyo", out var tokyoOffset);

            // Guard: if the host cannot actually switch zones, the comparison below proves
            // nothing, and a test that proves nothing while passing is worse than no test.
            Assert.NotEqual(newYorkOffset, tokyoOffset);

            Assert.Equal(newYork, tokyo);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TZ", original);
            TimeZoneInfo.ClearCachedData();
        }
    }

    private static string RenderUnderZone(string tz, out TimeSpan localBaseOffset)
    {
        Environment.SetEnvironmentVariable("TZ", tz);
        TimeZoneInfo.ClearCachedData();

        localBaseOffset = TimeZoneInfo.Local.BaseUtcOffset;
        return Render();
    }

    [Fact]
    public void TheSameInputDecodedTwiceProducesIdenticalOutput()
    {
        Assert.Equal(Render(), Render());
    }

    [Fact]
    public void RenderedOutputIsStableAcrossRepeatedDecodesOfTheSameInput()
    {
        // A library that stamped "when was this read" into a result, or that let enumeration
        // order reach the output, would break here rather than in any of the parse tests.
        var renders = Enumerable.Range(0, 5).Select(_ => Render()).Distinct().ToArray();

        Assert.Single(renders);
    }
}
