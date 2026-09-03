using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>Descriptors that lie: every one Failed, none thrown.</summary>
public sealed class DescriptorMalformedTests
{
    private static IdentityResult<SecurityDescriptor> Decode(Fx.DescriptorBuilder b) => DescriptorDecoder.Decode(b.Build());

    private static void AssertFailed(IdentityResult<SecurityDescriptor> result, string reasonFragment, long? position = null)
    {
        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Null(result.Value);
        Assert.Contains(reasonFragment, result.Reason, StringComparison.Ordinal);
        if (position is { } p)
        {
            Assert.Equal(p, result.Position);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(19)]
    public void ABufferShorterThanTheHeaderIsFailed(int length)
    {
        AssertFailed(DescriptorDecoder.Decode(new byte[length]), "needs 20 bytes", 0);
    }

    [Fact]
    public void TheSelfRelativeBitClearIsFailedNamingTheBit()
    {
        var b = Fx.Ordinary();
        b.ControlOverride = 0x0004;
        AssertFailed(Decode(b), "0x8000", 2);
    }

    [Fact]
    public void AnUnrecognisedDescriptorRevisionIsIncomplete()
    {
        var b = Fx.Ordinary();
        b.Revision = 2;
        var result = Decode(b);

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("revision 2", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOwnerOffsetOutsideTheDescriptorIsFailed()
    {
        var b = Fx.Ordinary();
        b.OwnerOffsetOverride = 0x1000;
        AssertFailed(Decode(b), "owner identifier offset 0x1000 points outside", 0x1000);
    }

    [Fact]
    public void AnOwnerOffsetAtTheVeryEndIsFailedOnTheOffsetNotOnTheRead()
    {
        var b = Fx.Ordinary();
        b.OwnerOffsetOverride = (uint)b.Build().Length;
        AssertFailed(Decode(b), "points outside");
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(4u)]
    [InlineData(19u)]
    public void AnOffsetInsideTheHeaderIsFailed(uint offset)
    {
        // "Before itself": the header is the only thing before the first structure, and an offset
        // into it is a structure pointing at its own container.
        var b = Fx.Ordinary();
        b.GroupOffsetOverride = offset;
        AssertFailed(Decode(b), "group identifier offset", offset);
        Assert.Contains("inside the 20-byte descriptor header", Decode(b).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void OwnerAndGroupPointingAtTheSameBytesIsFailedAsAnOverlap()
    {
        // "At each other". Revert: drop the claimed-range check, and two structures share bytes.
        var b = Fx.Ordinary();
        b.GroupOffsetOverride = 20;
        AssertFailed(Decode(b), "group identifier at 0x14–0x24 overlaps owner identifier at 0x14–0x24", 20);
    }

    [Fact]
    public void TheTwoListsPointingAtTheSameBytesIsFailedAsAnOverlap()
    {
        var b = Fx.Ordinary();
        b.SystemList = Fx.List(Fx.Audit(Fx.Everyone));
        b.DiscretionaryOffsetOverride = 48; // the system list's offset
        AssertFailed(Decode(b), "discretionary list at 0x30–0x38 overlaps system list at 0x30–0x38", 48);
    }

    [Fact]
    public void AListOffsetLandingInsideTheOwnerIsFailedAsAnOverlap()
    {
        var b = Fx.Ordinary();
        b.DiscretionaryOffsetOverride = 24; // four bytes into the owner identifier
        AssertFailed(Decode(b), "overlaps owner identifier");
    }

    [Fact]
    public void AnOwnerOffsetLandingInsideTheDiscretionaryListIsFailedAsAnOverlap()
    {
        // The self-referential chain: the owner "is" part of a list that is itself read later.
        // Claimed ranges catch it whichever order the structures are visited in.
        var b = Fx.Ordinary();
        b.ListsFirst = true;
        b.OwnerOffsetOverride = 28; // the first entry's header inside the list at 20
        AssertFailed(Decode(b), "overlaps");
    }

    [Fact]
    public void TheTransposedListFixture_TheDecoderFollowsTheOffsetsNotTheContent()
    {
        // Correct layout: 0x0C is the system list, 0x10 the discretionary. The system list holds
        // an audit entry, the discretionary an allow entry, so a decoder that reads the two
        // offsets in the other order shows type 0x00 under the system list. Revert: swap the
        // two reads in DescriptorDecoder and the first assertion block fails.
        var b = new Fx.DescriptorBuilder { SystemList = Fx.List(Fx.Audit(Fx.Everyone)), DiscretionaryList = Fx.List(Fx.Allow(Fx.Everyone)) };
        var d = Fx.Decode(b);
        Assert.Equal(EntryType.SystemAudit, ((AccessControlEntry.Decoded)((AccessControlList.Entries)d.SystemList).Items[0]).Type);
        Assert.Equal(EntryType.AccessAllowed, ((AccessControlEntry.Decoded)((AccessControlList.Entries)d.DiscretionaryList).Items[0]).Type);

        // The same bytes with the two header offsets transposed parse cleanly and are entirely
        // wrong — which is why the field order matters and why this is a fixture.
        b.SwapListOffsets = true;
        var swapped = Fx.Decode(b);
        Assert.Equal(EntryType.AccessAllowed, ((AccessControlEntry.Decoded)((AccessControlList.Entries)swapped.SystemList).Items[0]).Type);
        Assert.Equal(EntryType.SystemAudit, ((AccessControlEntry.Decoded)((AccessControlList.Entries)swapped.DiscretionaryList).Items[0]).Type);
        Assert.NotEqual(Fx.Render(d), Fx.Render(swapped));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(7)]
    public void AListHeaderWhoseSizeIsSmallerThanItselfIsFailed(int size)
    {
        var list = Fx.List(2, new[] { Fx.Allow(Fx.Everyone) }, declaredSize: (ushort)size);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), $"declared size {size} is smaller than its own 8-byte header", 22);
    }

    [Fact]
    public void AListWhoseSizeRunsPastTheDescriptorIsFailed()
    {
        var list = Fx.List(2, new[] { Fx.Allow(Fx.Everyone) }, declaredSize: 29);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "declared size 29 runs past the end of the descriptor", 22);
    }

    [Fact]
    public void AListTruncatedByTheBufferIsFailedNotPartiallyRead()
    {
        // Revert: walk to the count and let the buffer end stop you, and this is a two-entry
        // list that "read" one entry and called it Ok.
        var full = new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(Fx.Allow(Fx.Everyone), Fx.Allow(Fx.Administrators)) }.Build();
        var truncated = full.AsSpan(0, full.Length - 10);

        var result = DescriptorDecoder.Decode(truncated);
        AssertFailed(result, "runs past the end of the descriptor");
    }

    [Fact]
    public void AListHeaderCutByTheDescriptorEndIsFailed()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, ExtraControl = 0x0004, DiscretionaryOffsetOverride = 28 };
        AssertFailed(Decode(b), "header needs 8 bytes, only 4 remain", 28);
    }

    [Fact]
    public void AnEntrySizeOfZeroIsFailedAsANonAdvancingWalk()
    {
        // The canary for the loop guard. Revert: advance by max(size, 4) "to be lenient", and
        // this reads the same bytes as the next entry.
        var list = Fx.List(Fx.Entry(0x00, 0, 1, Fx.Everyone, declaredSize: 0));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "declared size 0 would not advance the walk", 30);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(21)]
    public void AnEntrySizeThatIsNotAMultipleOfFourIsFailed(int size)
    {
        var list = Fx.List(Fx.Entry(0x00, 0, 1, Fx.Everyone, declaredSize: (ushort)size));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), $"declared size {size} is not a multiple of 4", 30);
    }

    [Fact]
    public void AnEntrySizeOfFourHasNoRoomForTheMask()
    {
        var list = Fx.List(Fx.Entry(0x00, 0, 1, Fx.Everyone, declaredSize: 4), Fx.Allow(Fx.Everyone));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "no room for the access mask", 30);
    }

    [Fact]
    public void AnEntrySizeRunningPastTheListsDeclaredEndIsFailed()
    {
        // The descriptor continues past the list (trailing bytes), so the entry fits in the
        // buffer and only overruns the list. Revert: bound the entry by the buffer instead of the
        // list's declared end, and this decodes.
        var list = Fx.List(Fx.Entry(0x00, 0, 1, Fx.Everyone, declaredSize: 24));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list, TrailingBytes = 16 }), "declared size 24 runs past the list's declared end", 30);
    }

    [Fact]
    public void AnEntryCountOf0xFFFFOnASixtyByteListIsFailedAtTheEntryThatRunsOut()
    {
        // 8-byte header + two 20-byte entries + 12 bytes of padding = 60. Entry 2's header fits
        // in the padding and declares size 0; entry 3 would not fit at all. Either way it is
        // Failed, never 65535 "entries".
        var list = Fx.List(2, new[] { Fx.Allow(Fx.Everyone), Fx.Allow(Fx.Everyone) }, declaredCount: 0xFFFF, padding: 12);
        Assert.Equal(60, list.Length);
        var result = Decode(new Fx.DescriptorBuilder { DiscretionaryList = list });

        AssertFailed(result, "entry 2 at 0x44");
    }

    [Fact]
    public void AnEntryCountLargerThanTheEntriesPresentIsFailed()
    {
        var list = Fx.List(2, new[] { Fx.Allow(Fx.Everyone), Fx.Allow(Fx.Everyone) }, declaredCount: 3);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "entry 2 at 0x44: header needs 4 bytes, only 0 remain");
    }

    [Fact]
    public void AnEntryWhoseTrailerRunsPastItsDeclaredEndIsFailed()
    {
        // The trailer says five sub-authorities; the entry has room for one. Revert: read the
        // trailer from the descriptor buffer instead of the entry slice, and it "succeeds" by
        // reading the next entry's bytes.
        var entry = Fx.Allow(Fx.Sid(18));
        entry[8 + 1] = 5; // sub-authority count inside the trailer
        var list = Fx.List(entry, Fx.Allow(Fx.Administrators));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "trailer identifier at 0x24 runs past the entry's declared end at 0x30", 0x24 + 1);
    }

    [Fact]
    public void ATrailerWithACountAboveTheBoundIsFailed()
    {
        var entry = Fx.Allow(Fx.Sid(18));
        entry[8 + 1] = 16;
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(entry) }), "exceeds the bound of 15");
    }

    [Fact]
    public void AnObjectEntryWhoseTypeIdentifierRunsPastItsEndIsFailed()
    {
        var entry = Fx.ObjectEntry(0x05, 0, 1, 3, Guid.Empty, Guid.Empty, Fx.Everyone, declaredSize: 24);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(4, new[] { entry }) }), "object type identifier runs past the entry's declared end");
    }

    [Fact]
    public void AnObjectEntryWithNoRoomForItsFlagsIsFailed()
    {
        var entry = Fx.ObjectEntry(0x05, 0, 1, 0, null, null, Fx.Everyone, declaredSize: 8);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(4, new[] { entry }) }), "no room for the object flags");
    }

    [Fact]
    public void AnObjectEntryInARevisionTwoListIsFailed()
    {
        // The header and the entries disagree about what the list is.
        var entry = Fx.ObjectEntry(0x05, 0, 1, 0, null, null, Fx.Everyone);
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(2, new[] { entry }) }), "object-form entry type 0x05 in a revision-2 list", 28);
    }

    [Fact]
    public void AnUnrecognisedListRevisionIsIncompleteNotDecodedUnderAnAssumedLayout()
    {
        var result = Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(3, new[] { Fx.Allow(Fx.Everyone) }) });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("unrecognised list revision 3", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOwnerIdentifierThatOverrunsTheDescriptorIsFailedWithAnAbsolutePosition()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.SidWithCount(9, 18) };
        AssertFailed(Decode(b), "owner identifier at 0x14: sub-authority count 9", 21);
    }

    [Fact]
    public void AnUnknownEntryTypeStillHasItsSizeValidated()
    {
        var list = Fx.List(Fx.Entry(0x04, 0, 0, Fx.Everyone, declaredSize: 0));
        AssertFailed(Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }), "would not advance");
    }

    [Fact]
    public void EveryTruncationOfAFullDescriptorIsFailedOrIncompleteNeverOkNeverThrown()
    {
        var b = Fx.Ordinary();
        b.SystemList = Fx.List(4, new[] { Fx.ObjectEntry(0x07, 0xC0, 1, 3, Guid.NewGuid(), Guid.NewGuid(), Fx.Everyone), Fx.Entry(0x0D, 0, 1, Fx.LocalSystem, new byte[] { 1, 2, 3, 4 }) });
        var full = b.Build();
        Assert.Equal(IdentityResultState.Ok, DescriptorDecoder.Decode(full).State);

        for (var length = 0; length < full.Length; length++)
        {
            var result = DescriptorDecoder.Decode(full.AsSpan(0, length));
            Assert.NotEqual(IdentityResultState.Ok, result.State);
        }
    }

    [Fact]
    public void ASeededSweepOfSingleByteCorruptionsNeverThrows()
    {
        var b = Fx.Ordinary();
        b.SystemList = Fx.List(4, new[] { Fx.ObjectEntry(0x05, 0, 1, 1, Guid.Empty, null, Fx.Everyone), Fx.Entry(0x11, 0, 3, Fx.MediumLabel) });
        var full = b.Build();
        var random = new Random(0x5C7E);

        for (var i = 0; i < 5000; i++)
        {
            var mutated = (byte[])full.Clone();
            var count = 1 + random.Next(3);
            for (var j = 0; j < count; j++)
            {
                mutated[random.Next(mutated.Length)] = (byte)random.Next(256);
            }

            // Not asserting a state: any of the three is legitimate. Asserting only that the
            // decoder returned rather than threw.
            _ = DescriptorDecoder.Decode(mutated, ObjectKind.File);
        }
    }

    [Fact]
    public void EveryOffsetFieldSweptOverTheWholeBufferNeverThrows()
    {
        var full = Fx.Ordinary().Build();
        for (var field = 4; field <= 16; field += 4)
        {
            for (uint offset = 0; offset <= full.Length + 4; offset++)
            {
                var mutated = (byte[])full.Clone();
                BitConverter.TryWriteBytes(mutated.AsSpan(field, 4), offset);
                _ = DescriptorDecoder.Decode(mutated);
            }
        }
    }
}
