using System.Text;
using Scythe.Techniques.Tests.Fixtures;
using Xunit;

namespace Scythe.Techniques.Tests;

/// <summary>Map files that are not the format at all, or are broken at the byte level.</summary>
public sealed class MapMalformedTests
{
    [Fact]
    public void AFileThatIsNotJsonIsFailedWithAPosition()
    {
        var result = TechniqueMapLoader.Load("this is not json");

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.NotNull(result.Position);
        Assert.Contains("not well-formed JSON at offset 0x", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyFileIsFailed()
    {
        var result = TechniqueMapLoader.Load(Array.Empty<byte>());

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Equal(0, result.Position);
        Assert.Contains("empty", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AWhitespaceOnlyFileIsFailed()
    {
        var result = TechniqueMapLoader.Load("  \n\t ");

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void ATruncatedFileIsFailedAtTheCut()
    {
        var bytes = MapFixtures.Standard().Bytes();
        var cut = bytes.Length / 2;

        var result = TechniqueMapLoader.Load(bytes.AsMemory(0, cut));

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.NotNull(result.Position);
        Assert.InRange(result.Position!.Value, 0, cut);
    }

    [Fact]
    public void ABomPrefixedSyntaxErrorReportsAFileRelativePosition()
    {
        var body = Encoding.UTF8.GetBytes("{\"entries\":[}");
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(body).ToArray();

        var withBom = TechniqueMapLoader.Load(bytes);
        var without = TechniqueMapLoader.Load(body);

        Assert.Equal(TechniqueResultState.Failed, withBom.State);
        Assert.Equal(without.Position!.Value + 3, withBom.Position!.Value);
    }

    [Fact]
    public void TrailingGarbageAfterAValidObjectIsFailed()
    {
        var result = TechniqueMapLoader.Load(MapFixtures.Standard().Json() + " trailing");

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void ASecondRootValueIsFailed()
    {
        var result = TechniqueMapLoader.Load(MapFixtures.Standard().Json() + "{}");

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void CommentsAreNotAccepted()
    {
        var result = TechniqueMapLoader.Load("{/* c */\"entries\":[]}");

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void ATrailingCommaIsNotAccepted()
    {
        var result = TechniqueMapLoader.Load("{\"entries\":[],}");

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void NestingInsideTheBudgetButOutsideTheSchemaIsFailedNotIncomplete()
    {
        // Depth 5 under the default depth budget of 16: the file is well-formed and wrong.
        var result = TechniqueMapLoader.Load("{\"entries\":[[[[]]]]}");

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("entries[0]", result.Reason, StringComparison.Ordinal);
        Assert.Contains("array", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEnormousFlatEntryListUnderTheDefaultBudgetLoads()
    {
        // 5,000 entries is large but inside MaxMatches; it must be an ordinary load, so the
        // budget canary in BudgetCanaryTests is shown to bite on the count and nothing else.
        var builder = new MapBuilder();
        for (var i = 0; i < 5000; i++)
        {
            builder.Entry($"T{i:D4}");
        }

        var result = builder.Load();

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(5000, result.Value!.Count);
    }

    [Fact]
    public void InvalidUtf8InsideAStringIsFailed()
    {
        var good = MapFixtures.Standard().Bytes();
        var bad = (byte[])good.Clone();
        // Overwrite the first byte of the first name with a lone continuation byte.
        var nameAt = Array.IndexOf(bad, (byte)'S', Encoding.UTF8.GetByteCount("{\"entries\":[{\"id\":\"T1053\",\"name\":\""));
        bad[nameAt] = 0x80;

        var result = TechniqueMapLoader.Load(bad);

        Assert.Equal(TechniqueResultState.Failed, result.State);
    }

    [Fact]
    public void EveryByteMutationOfTheStandardMapIsHandledWithoutThrowing()
    {
        // Seeded, so the sweep is the same every run. Each mutation is loaded under the
        // default budget and any of the three states is acceptable; throwing is not.
        var original = MapFixtures.Standard().Bytes();
        var rng = new Random(0x4B34);
        var states = new Dictionary<TechniqueResultState, int>();

        for (var i = 0; i < original.Length; i++)
        {
            var mutated = (byte[])original.Clone();
            mutated[i] = (byte)rng.Next(256);
            var result = TechniqueMapLoader.Load(mutated);
            states[result.State] = states.GetValueOrDefault(result.State) + 1;
        }

        // Most mutations break something; a few land in a name and are harmless.
        Assert.True(states.GetValueOrDefault(TechniqueResultState.Failed) > original.Length / 2);
        Assert.True(states.GetValueOrDefault(TechniqueResultState.Ok) > 0);
    }

    [Fact]
    public void EveryTruncationOfTheStandardMapIsHandledWithoutThrowing()
    {
        var original = MapFixtures.Standard().Bytes();

        for (var length = 0; length < original.Length; length++)
        {
            var result = TechniqueMapLoader.Load(original.AsMemory(0, length));
            Assert.Equal(TechniqueResultState.Failed, result.State);
        }
    }
}
