namespace Scythe.Intel.Tests;

using Xunit;
using Scythe.Intel;

/// <summary>Every defang form from the task brief restored, plus the no-change path. Miss a
/// form and a whole feed silently yields nothing — hence one test per form.</summary>
public class DefangerTests
{
    [Theory]
    // Schemes
    [InlineData("hxxp://evil.com/a", "http://evil.com/a")]
    [InlineData("hxxps://evil.com/a", "https://evil.com/a")]
    [InlineData("HXXP://evil.com/a", "http://evil.com/a")]
    [InlineData("fxp://evil.com/a", "ftp://evil.com/a")]
    [InlineData("meow://evil.com/a", "http://evil.com/a")]
    [InlineData("meows://evil.com/a", "https://evil.com/a")]
    // Dots, three bracket shapes
    [InlineData("1.2.3[.]4", "1.2.3.4")]
    [InlineData("example(.)org", "example.org")]
    [InlineData("example{.}org", "example.org")]
    // "dot" words
    [InlineData("evil[dot]com", "evil.com")]
    [InlineData("evil(dot)com", "evil.com")]
    [InlineData("evil{dot}com", "evil.com")]
    [InlineData("evil[DOT]com", "evil.com")]
    // Space-padded
    [InlineData("evil [dot] com", "evil.com")]
    [InlineData("evil [.] com", "evil.com")]
    [InlineData("1.2.3 [.] 4", "1.2.3.4")]
    // At-signs
    [InlineData("mail[@]domain.com", "mail@domain.com")]
    [InlineData("mail(@)domain.com", "mail@domain.com")]
    [InlineData("mail[at]domain.com", "mail@domain.com")]
    [InlineData("mail (at) domain.com", "mail@domain.com")]
    // Colons
    [InlineData("hxxp[:]//evil.com", "http://evil.com")]
    [InlineData("hxxp[://]evil.com", "http://evil.com")]
    [InlineData("hxxp(://)evil.com", "http://evil.com")]
    // Combinations
    [InlineData("hxxps://evil[dot]com/path", "https://evil.com/path")]
    public void DefangedForm_IsRestored(string defanged, string expected)
    {
        var restored = Defanger.Restore(defanged, out var wasDefanged);
        Assert.Equal(expected, restored);
        Assert.True(wasDefanged);
    }

    [Theory]
    [InlineData("http://ok.example/a")]
    [InlineData("1.2.3.4")]
    [InlineData("evil.com")]
    [InlineData("mail@domain.com")]
    public void CleanValue_IsUntouched_AndNotFlagged(string value)
    {
        var restored = Defanger.Restore(value, out var wasDefanged);
        Assert.Equal(value, restored);
        Assert.False(wasDefanged);
    }

    [Fact]
    public void PipelineRecordsDefanging_OnTheIndicator()
    {
        var result = TestData.IngestLines("hxxp://evil.example/x", "http://clean.example/y");
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(2, result.Indicators.Count);

        var defanged = result.Indicators[0];
        Assert.Equal("http://evil.example/x", defanged.Value);
        Assert.Equal("hxxp://evil.example/x", defanged.RawValue);
        Assert.True(defanged.WasDefanged);
        Assert.False(result.Indicators[1].WasDefanged);
    }

    [Fact]
    public void DefangedIp_RestoresBeforeTypeInference()
    {
        // The family of "1.2.3[.]4" is only inferable after restoration; this pins the
        // restore-then-infer ordering.
        var result = TestData.IngestLines("1.2.3[.]4");
        var ind = Assert.Single(result.Indicators);
        Assert.Equal(IndicatorType.Ipv4, ind.Type);
        Assert.Equal("1.2.3.4", ind.Value);
        Assert.True(ind.WasDefanged);
    }
}
