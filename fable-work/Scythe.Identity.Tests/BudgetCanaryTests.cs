using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>
/// Canaries: inputs known to trip each budget dimension, asserted Incomplete, with a negative
/// control showing the same input passes under a budget that does not bind.
/// </summary>
public sealed class BudgetCanaryTests
{
    /// <summary>The largest list a 16-bit size field can hold: 4095 sixteen-byte entries.</summary>
    private static byte[] LargestList()
    {
        var entry = Fx.Allow(Fx.SidOf(1, 5));
        Assert.Equal(16, entry.Length);
        var entries = Enumerable.Repeat(entry, 4095).ToArray();
        var list = Fx.List(entries);
        Assert.Equal(8 + 4095 * 16, list.Length);
        return list;
    }

    [Fact]
    public void DefaultBudgetHasTheValuesTheSharedContractStates()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), ScanBudget.Default.Deadline);
        Assert.Equal(64L * 1024 * 1024, ScanBudget.Default.MaxInputBytes);
        Assert.Equal(10_000, ScanBudget.Default.MaxMatches);
        Assert.Equal(16, ScanBudget.Default.MaxNestingDepth);
    }

    [Fact]
    public void ADescriptorPastTheByteBudgetIsIncompleteWithTheBudgetNamed()
    {
        var bytes = Fx.Ordinary().Build();
        var result = DescriptorDecoder.Decode(bytes, null, ScanBudget.Default with { MaxInputBytes = bytes.Length - 1 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains($"budget allows {bytes.Length - 1}", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADescriptorExactlyAtTheByteBudgetDecodes()
    {
        var bytes = Fx.Ordinary().Build();
        Assert.Equal(IdentityResultState.Ok, DescriptorDecoder.Decode(bytes, null, ScanBudget.Default with { MaxInputBytes = bytes.Length }).State);
    }

    [Fact]
    public void AMultiMegabyteBufferIsRefusedBeforeAnyParsing()
    {
        // A list's size field is 16 bits, so "several megabytes of entries" cannot be encoded as
        // a list — what a caller can hand in is several megabytes of buffer, and that is refused
        // on the byte budget before a single offset is read.
        var huge = new byte[3 * 1024 * 1024];
        Fx.Ordinary().Build().CopyTo(huge, 0);
        var result = DescriptorDecoder.Decode(huge, null, ScanBudget.Default with { MaxInputBytes = 1024 * 1024 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("budget allows", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLargestEncodableListStopsAtMaxMatches()
    {
        // Revert: drop the MaxMatches check and all 4095 come back under a budget of 100.
        var bytes = new Fx.DescriptorBuilder { DiscretionaryList = LargestList() }.Build();
        var result = DescriptorDecoder.Decode(bytes, null, ScanBudget.Default with { MaxMatches = 100 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Contains("budget allows 100 entries", result.Reason, StringComparison.Ordinal);
        Assert.Contains("100 of 4095", result.Reason, StringComparison.Ordinal);
        Assert.Equal(100, Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList).Items.Count);
    }

    [Fact]
    public void TheLargestEncodableListDecodesInFullUnderTheDefaultBudget()
    {
        // Negative control: the guard is quiet when it does not bind.
        var bytes = new Fx.DescriptorBuilder { DiscretionaryList = LargestList() }.Build();
        var result = DescriptorDecoder.Decode(bytes);

        Assert.Equal(IdentityResultState.Ok, result.State);
        Assert.Equal(4095, Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList).Items.Count);
    }

    [Fact]
    public void MaxMatchesCountsAcrossBothLists()
    {
        // Two lists of 4095 each is 8190 entries; a budget of 5000 lets the system list finish
        // and stops the discretionary list at 905. Revert: count per list, and both come back whole.
        var bytes = new Fx.DescriptorBuilder { SystemList = LargestList(), DiscretionaryList = LargestList() }.Build();
        var result = DescriptorDecoder.Decode(bytes, null, ScanBudget.Default with { MaxMatches = 5000 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Equal(4095, Assert.IsType<AccessControlList.Entries>(result.Value!.SystemList).Items.Count);
        Assert.Equal(905, Assert.IsType<AccessControlList.Entries>(result.Value.DiscretionaryList).Items.Count);
        Assert.Contains("discretionary list: stopped after 905 of 4095", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void BothListsFullIsUnderTheDefaultBudgetAndOk()
    {
        var bytes = new Fx.DescriptorBuilder { SystemList = LargestList(), DiscretionaryList = LargestList() }.Build();
        Assert.Equal(IdentityResultState.Ok, DescriptorDecoder.Decode(bytes).State);
    }

    [Fact]
    public void AMaxMatchesOfZeroStopsBeforeTheFirstEntryButStillReportsTheList()
    {
        var bytes = Fx.Ordinary().Build();
        var result = DescriptorDecoder.Decode(bytes, null, ScanBudget.Default with { MaxMatches = 0 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        var list = Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList);
        Assert.Empty(list.Items);
        Assert.Equal(3, list.Header.DeclaredCount);
    }

    [Fact]
    public void AStoppedListIsNeverMistakenForAnEmptyOne()
    {
        // Presence is Entries (declared count 3) even though nothing was collected. A revert that
        // derived presence from the collected items would call this Empty — "grants nothing".
        var result = DescriptorDecoder.Decode(Fx.Ordinary().Build(), null, ScanBudget.Default with { MaxMatches = 0 });

        Assert.Equal(ListPresence.Entries, result.Value!.DiscretionaryList.Presence);
    }

    [Fact]
    public void AZeroDeadlineIsIncompleteNamingTheDeadline()
    {
        var result = DescriptorDecoder.Decode(Fx.Ordinary().Build(), null, ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("deadline", result.Reason, StringComparison.Ordinal);
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void AnIdentifierPastTheByteBudgetIsIncomplete()
    {
        var result = IdentifierDecoder.Decode(Fx.Sid(18), ScanBudget.Default with { MaxInputBytes = 8 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("budget allows 8", result.Reason, StringComparison.Ordinal);
        Assert.Equal(IdentityResultState.Ok, IdentifierDecoder.Decode(Fx.Sid(18), ScanBudget.Default with { MaxInputBytes = 12 }).State);
    }

    [Fact]
    public void OmittingTheBudgetUsesTheDefaultRatherThanNoLimit()
    {
        var huge = new byte[ScanBudget.DefaultMaxInputBytes + 1];
        Assert.Equal(IdentityResultState.Incomplete, IdentifierDecoder.Decode(huge).State);
        Assert.Equal(IdentityResultState.Incomplete, DescriptorDecoder.Decode(huge).State);
    }

    [Fact]
    public void TheNonAdvancingEntryCanaryBites()
    {
        // The loop guard's canary, restated here so the resource-safety file has it: a size-zero
        // entry with count 0xFFFF would spin forever without the guard.
        var list = Fx.List(2, new[] { Fx.Entry(0x00, 0, 1, Fx.Everyone, declaredSize: 0) }, declaredCount: 0xFFFF);
        var result = DescriptorDecoder.Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }.Build());

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Contains("would not advance", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheOverlapCanaryBites()
    {
        // Every one of the four offsets pointing at the same list: the first is claimed, the
        // second is refused. Without claimed-range tracking this parses "cleanly".
        var b = Fx.Ordinary();
        b.OwnerOffsetOverride = 48;
        b.GroupOffsetOverride = 48;
        b.SystemOffsetOverride = 48;
        b.ExtraControl = 0x0010;
        var result = DescriptorDecoder.Decode(b.Build());

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Contains("overlaps", result.Reason, StringComparison.Ordinal);
    }
}
