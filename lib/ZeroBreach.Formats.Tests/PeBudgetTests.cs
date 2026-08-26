using ZeroBreach.Formats;
using ZeroBreach.Formats.Pe;
using Xunit;

namespace ZeroBreach.Formats.Tests;

/// <summary>
/// Budget enforcement. Includes the mandatory canary (BLUEPRINT §3): an input *known* to
/// exceed its budget, asserted to come back budgeted-out — without it this whole section
/// could silently become a no-op.
/// </summary>
public sealed class PeBudgetTests
{
    private static readonly byte[] Code = { 0xC3, 0x90, 0x90, 0x90 };

    private static PeFixtureBuilder RichFixture()
    {
        var b = new PeFixtureBuilder();
        uint va = b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(va);
        b.AddImports(new ImportDll("KERNEL32.dll", ImportFunc.ByName("ExitProcess")));
        b.AddExports("SELF.dll", 1, new ExportSpec("Go", va));
        b.AddResources(ResSpec.Leaf(1u, new byte[] { 1, 2, 3 }));
        return b;
    }

    [Fact]
    public void InputLargerThanMaxInputBytes_IsRefusedAsIncomplete_NotSilentlyParsed()
    {
        byte[] file = RichFixture().Build();
        var budget = BudgetDefaults.Default with { MaxInputBytes = 64 };
        var r = PeParser.Parse(file, budget);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains("MaxInputBytes", r.Message);
        Assert.Null(r.Image); // refused before parsing — no partial claim of coverage
        Assert.Null(r.Metrics);
    }

    [Fact]
    public void Canary_ZeroDeadline_IsBudgetedOutAsIncomplete_NeverSilentNoMatch()
    {
        // CANARY: a zero deadline is exceeded by construction. If this stops returning
        // Incomplete with a time-budget reason, deadline enforcement has silently died.
        byte[] file = RichFixture().Build();
        var budget = BudgetDefaults.Default with { Deadline = TimeSpan.Zero };
        var r = PeParser.Parse(file, budget);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("time budget"));
        // Headers were parsed before the budget gate; the directory walks were skipped.
        Assert.NotNull(r.Image);
        Assert.Empty(r.Image!.Imports);
        Assert.Null(r.Image!.Exports);
        Assert.Null(r.Image!.ResourceRoot);
        // Metrics over the raw bytes are still produced — coverage is reported honestly.
        Assert.NotNull(r.Metrics);
        Assert.NotNull(r.Metrics!.WholeFileEntropy);
    }

    [Fact]
    public void GenerousDeadline_SameFixture_ParsesEverything()
    {
        // The counterpart proving the canary's Incomplete is the budget's doing, not the file's.
        byte[] file = RichFixture().Build();
        var r = PeParser.Parse(file, BudgetDefaults.Default);

        Assert.Equal(OperationState.Ok, r.State);
        Assert.Single(r.Image!.Imports);
        Assert.NotNull(r.Image!.Exports);
        Assert.NotNull(r.Image!.ResourceRoot);
    }

    [Fact]
    public void SameInput_SameBudget_ProducesIdenticalResults()
    {
        // Determinism (BLUEPRINT §2): same rules + same input = same result set, same order.
        var b = RichFixture();
        b.AddDebug(new Guid("11111111-2222-3333-4444-555555555555"), 1, @"C:\x\y.pdb");
        b.AddTls(b.ImageBase + 0x1000);
        b.AddCertificate(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        byte[] file = b.Build();

        string first = TestParse.Dump(TestParse.Run(file));
        string second = TestParse.Dump(TestParse.Run(file));
        Assert.Equal(first, second);
        Assert.NotEmpty(first);
    }

    [Fact]
    public void HostileInput_IsAlsoDeterministic()
    {
        var b = new PeFixtureBuilder { SectionCountOverride = 65535 };
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] file = b.Build();

        Assert.Equal(TestParse.Dump(TestParse.Run(file)), TestParse.Dump(TestParse.Run(file)));
    }
}
