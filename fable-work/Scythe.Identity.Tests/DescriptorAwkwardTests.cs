using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>Valid but awkward descriptors: the corners §11.3 names.</summary>
public sealed class DescriptorAwkwardTests
{
    private static readonly Guid TypeA = new("11111111-2222-3333-4444-555555555555");
    private static readonly Guid TypeB = new("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    private static AccessControlEntry.Decoded SingleEntry(byte[] list, ObjectKind? kind = null)
    {
        var d = Fx.Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }, kind);
        return Assert.IsType<AccessControlEntry.Decoded>(Assert.Single(Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList).Items));
    }

    [Theory]
    [InlineData(0u, false, false)]
    [InlineData(1u, true, false)]
    [InlineData(2u, false, true)]
    [InlineData(3u, true, true)]
    public void AnObjectEntryCarriesEachTypeIdentifierOnlyWhenItsBitIsSet(uint objectFlags, bool hasType, bool hasInherited)
    {
        // Revert: always read both identifiers, and the trailer shifts by 16 or 32 bytes in the
        // three cases where a bit is clear — the fixture puts the trailer where the flags say.
        var entry = Fx.ObjectEntry(0x05, 0, 0x0001_0000, objectFlags, hasType ? TypeA : null, hasInherited ? TypeB : null, Fx.Administrators, new byte[] { 0xEE, 0xEE, 0xEE, 0xEE });
        var e = SingleEntry(Fx.List(4, new[] { entry }));

        Assert.Equal(EntryType.AccessAllowedObject, e.Type);
        Assert.Equal((ObjectTypeFlags)objectFlags, e.ObjectTypes!.Flags);
        Assert.Equal(hasType ? TypeA : null, e.ObjectTypes.ObjectType);
        Assert.Equal(hasInherited ? TypeB : null, e.ObjectTypes.InheritedObjectType);
        Assert.Equal("S-1-5-32-544", e.Trailer.ToCanonicalString());
        Assert.Equal(4, e.SurplusBytes);
        Assert.Equal(MaskInterpretation.AccessRights, e.MaskInterpretation);
    }

    [Fact]
    public void ACallbackEntryKeepsItsApplicationDataRawWithItsOffset()
    {
        var data = new byte[] { 0x61, 0x72, 0x74, 0x78, 0x01, 0x02, 0x03, 0x04 };
        var e = SingleEntry(Fx.List(Fx.Entry(0x09, 0, 0x0012_0089, Fx.Everyone, data)));

        Assert.Equal(EntryType.AccessAllowedCallback, e.Type);
        Assert.Equal("S-1-1-0", e.Trailer.ToCanonicalString());
        Assert.NotNull(e.ApplicationData);
        Assert.Equal(data, e.ApplicationData!.Bytes);
        Assert.Equal(28 + 8 + 12, e.ApplicationData.Offset);
        Assert.Equal(0, e.SurplusBytes);
        Assert.NotNull(e.Rights);
    }

    [Fact]
    public void ACallbackObjectEntryCarriesBothTypeIdentifiersAndApplicationData()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var e = SingleEntry(Fx.List(4, new[] { Fx.ObjectEntry(0x0B, 0, 1, 3, TypeA, TypeB, Fx.LocalSystem, data) }));

        Assert.Equal(EntryType.AccessAllowedCallbackObject, e.Type);
        Assert.Equal(TypeA, e.ObjectTypes!.ObjectType);
        Assert.Equal(TypeB, e.ObjectTypes.InheritedObjectType);
        Assert.Equal("S-1-5-18", e.Trailer.ToCanonicalString());
        Assert.Equal(data, e.ApplicationData!.Bytes);
    }

    [Fact]
    public void AMandatoryLabelIsPolicyAndALevel_NotRights()
    {
        // Revert: run the ordinary mask decoder over it, and 0x3 becomes "Read data, Write data".
        var e = SingleEntry(Fx.List(Fx.Entry(0x11, 0, 0x3, Fx.MediumLabel)), ObjectKind.File);

        Assert.Equal(EntryType.MandatoryLabel, e.Type);
        Assert.Equal(MaskInterpretation.MandatoryLabelPolicy, e.MaskInterpretation);
        Assert.Null(e.Rights);
        Assert.Equal(LabelPolicy.NoWriteUp | LabelPolicy.NoReadUp, e.LabelPolicy);
        Assert.Equal(8192u, e.IntegrityLevel);
        Assert.Equal("S-1-16-8192", e.Trailer.ToCanonicalString());
        Assert.Equal(0x3u, e.Mask);
    }

    [Fact]
    public void AMandatoryLabelWithNoSubAuthoritiesHasNoLevel()
    {
        var e = SingleEntry(Fx.List(Fx.Entry(0x11, 0, 0x1, Fx.SidOf(1, 16))));

        Assert.Null(e.IntegrityLevel);
        Assert.Equal(LabelPolicy.NoWriteUp, e.LabelPolicy);
    }

    [Theory]
    [InlineData(0x12, EntryType.ResourceAttribute, true)]
    [InlineData(0x13, EntryType.ScopedPolicyIdentifier, false)]
    [InlineData(0x14, EntryType.ProcessTrustLabel, false)]
    [InlineData(0x15, EntryType.AccessFilter, true)]
    public void TheTypesWhoseMaskTheReferenceDoesNotDefineAreKeptRaw(byte typeByte, EntryType type, bool carriesData)
    {
        var extra = new byte[] { 9, 9, 9, 9 };
        var e = SingleEntry(Fx.List(Fx.Entry(typeByte, 0, 0x0001_0003, Fx.LocalSystem, extra)), ObjectKind.File);

        Assert.Equal(type, e.Type);
        Assert.Equal(MaskInterpretation.NotInterpreted, e.MaskInterpretation);
        Assert.Null(e.Rights);
        Assert.Null(e.LabelPolicy);
        Assert.Equal(0x0001_0003u, e.Mask);
        Assert.Equal("S-1-5-18", e.Trailer.ToCanonicalString());
        if (carriesData)
        {
            Assert.Equal(extra, e.ApplicationData!.Bytes);
            Assert.Equal(0, e.SurplusBytes);
        }
        else
        {
            Assert.Null(e.ApplicationData);
            Assert.Equal(4, e.SurplusBytes);
        }
    }

    [Fact]
    public void AnEntryWhoseDeclaredSizeExceedsItsContentIsSkippedToItsDeclaredEnd()
    {
        // Eight padding bytes after the first trailer. Revert: advance by the decoded content
        // instead of the declared size, and the second entry is read from the padding.
        var list = Fx.List(Fx.Entry(0x00, 0, 1, Fx.Everyone, padding: 8), Fx.Allow(Fx.Administrators));
        var d = Fx.Decode(new Fx.DescriptorBuilder { DiscretionaryList = list });
        var items = Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList).Items;

        Assert.Equal(2, items.Count);
        var first = Assert.IsType<AccessControlEntry.Decoded>(items[0]);
        Assert.Equal(8, first.SurplusBytes);
        Assert.Equal(28, first.DeclaredSize);
        var second = Assert.IsType<AccessControlEntry.Decoded>(items[1]);
        Assert.Equal("S-1-5-32-544", second.Trailer.ToCanonicalString());
        Assert.Equal(28 + 28, second.Offset);
    }

    [Fact]
    public void AListWhoseDeclaredSizeExceedsTheSumOfItsEntriesReportsTheSurplus()
    {
        var list = Fx.List(2, new[] { Fx.Allow(Fx.Everyone) }, padding: 12);
        var d = Fx.Decode(new Fx.DescriptorBuilder { DiscretionaryList = list });
        var entries = Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList);

        Assert.Equal(12, entries.Header.SurplusBytes);
        Assert.Single(entries.Items);
    }

    [Fact]
    public void NoOwnerIsAbsentNotZero()
    {
        var b = Fx.Ordinary();
        b.Owner = null;
        var d = Fx.Decode(b);

        Assert.Null(d.Owner);
        Assert.Equal(0u, d.Offsets.Owner);
        Assert.NotNull(d.Group);
    }

    [Fact]
    public void NoGroupIsAbsentNotZero()
    {
        var b = Fx.Ordinary();
        b.Group = null;
        var d = Fx.Decode(b);

        Assert.Null(d.Group);
        Assert.NotNull(d.Owner);
    }

    [Fact]
    public void ASystemListWithoutADiscretionaryListDecodes()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, SystemList = Fx.List(Fx.Audit(Fx.Everyone)) };
        var d = Fx.Decode(b);

        Assert.IsType<AccessControlList.Entries>(d.SystemList);
        Assert.Equal(AbsenceEncoding.ControlBitClear, Assert.IsType<AccessControlList.NotPresent>(d.DiscretionaryList).Encoding);
    }

    [Fact]
    public void AnUnknownEntryTypeIsKeptRawAndMakesTheDescriptorIncomplete()
    {
        // Revert: return Ok when every entry parsed, and a caller comparing against a baseline
        // never learns it did not see everything.
        var list = Fx.List(Fx.Allow(Fx.Everyone), Fx.Entry(0x04, 0x10, 0xABCD, Fx.LocalSystem), Fx.Allow(Fx.Administrators));
        var result = DescriptorDecoder.Decode(new Fx.DescriptorBuilder { DiscretionaryList = list }.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("unknown entry type 0x04", result.Reason, StringComparison.Ordinal);
        Assert.Contains("discretionary list entry 1", result.Reason, StringComparison.Ordinal);
        Assert.NotNull(result.Value);

        var items = Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList).Items;
        Assert.Equal(3, items.Count);
        var unknown = Assert.IsType<AccessControlEntry.Unknown>(items[1]);
        Assert.Equal(0x04, unknown.TypeByte);
        Assert.Equal(0x10, unknown.FlagsRaw);
        Assert.Equal(20, unknown.DeclaredSize);
        Assert.Equal(28 + 20 + 4, unknown.Body.Offset);
        Assert.Equal(16, unknown.Body.Bytes.Count);
        Assert.Equal(new byte[] { 0xCD, 0xAB, 0, 0 }, unknown.Body.Bytes.Take(4));
        Assert.Equal("S-1-5-32-544", Assert.IsType<AccessControlEntry.Decoded>(items[2]).Trailer.ToCanonicalString());
    }

    [Fact]
    public void AnUnknownEntryTypeInTheSystemListNamesTheSystemList()
    {
        var b = new Fx.DescriptorBuilder { SystemList = Fx.List(Fx.Entry(0x0E, 0, 0, Fx.Everyone)), DiscretionaryList = Fx.List(Fx.Allow(Fx.Everyone)) };
        var result = DescriptorDecoder.Decode(b.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("system list entry 0: unknown entry type 0x0E", result.Reason, StringComparison.Ordinal);
        Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList);
    }

    [Theory]
    [InlineData(0x04)]
    [InlineData(0x08)]
    [InlineData(0x0E)]
    [InlineData(0x10)]
    [InlineData(0x16)]
    [InlineData(0xFF)]
    public void EveryTypeByteTheReferenceDoesNotTableIsUnknown(byte typeByte)
    {
        var result = DescriptorDecoder.Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(Fx.Entry(typeByte, 0, 0, Fx.Everyone)) }.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.IsType<AccessControlEntry.Unknown>(Assert.Single(Assert.IsType<AccessControlList.Entries>(result.Value!.DiscretionaryList).Items));
    }

    [Fact]
    public void ARevisionFourListWithOrdinaryEntriesIsOk()
    {
        var d = Fx.Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(4, new[] { Fx.Allow(Fx.Everyone) }) });

        Assert.Equal(4, Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList).Header.Revision);
    }

    [Fact]
    public void AnOwnerWithAnUnrecognisedRevisionIsIncompleteWithThePartialDescriptor()
    {
        var b = Fx.Ordinary();
        b.Owner = Fx.SidOf(3, 5, 32, 544);
        var result = DescriptorDecoder.Decode(b.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("owner identifier", result.Reason, StringComparison.Ordinal);
        Assert.Contains("revision 3", result.Reason, StringComparison.Ordinal);
        Assert.Equal("S-3-5-32-544", result.Value!.Owner!.ToCanonicalString());
        Assert.Equal(3, Assert.IsType<AccessControlList.Entries>(result.Value.DiscretionaryList).Items.Count);
    }

    [Fact]
    public void ATrailerWithAnUnrecognisedRevisionIsIncompleteNamingTheEntry()
    {
        var result = DescriptorDecoder.Decode(new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(Fx.Allow(Fx.SidOf(9, 5, 18))) }.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("discretionary list entry 0: trailer identifier", result.Reason, StringComparison.Ordinal);
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void SeveralReasonsAreAllReported()
    {
        var b = Fx.Ordinary();
        b.Owner = Fx.SidOf(3, 5, 32, 544);
        b.SystemList = Fx.List(Fx.Entry(0x08, 0, 0, Fx.Everyone));
        var result = DescriptorDecoder.Decode(b.Build());

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("owner identifier", result.Reason, StringComparison.Ordinal);
        Assert.Contains("system list entry 0", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AuditFlagsDecodeOnAuditEntries()
    {
        var e = SingleEntry(Fx.List(Fx.Entry(0x02, 0x40, 0x0001_0000, Fx.Everyone)));

        Assert.Equal(EntryFlags.SuccessfulAccessAudit, e.Flags);
        Assert.Equal(0x40, e.FlagsRaw);
    }

    [Fact]
    public void EveryInheritanceFlagDecodes()
    {
        var e = SingleEntry(Fx.List(Fx.Entry(0x00, 0x1F, 1, Fx.Everyone)));

        Assert.Equal(EntryFlags.ObjectInherit | EntryFlags.ContainerInherit | EntryFlags.NoPropagateInherit | EntryFlags.InheritOnly | EntryFlags.Inherited, e.Flags);
    }

    [Fact]
    public void ATrailerWithTheMaximumSubAuthorityCountFitsInAnEntry()
    {
        var subs = Enumerable.Range(1, 15).Select(i => (uint)i).ToArray();
        var e = SingleEntry(Fx.List(Fx.Allow(Fx.Sid(subs))));

        Assert.Equal(subs, e.Trailer.SubAuthorities);
        Assert.Equal(76, e.DeclaredSize);
    }

    [Fact]
    public void ATrailerWithZeroSubAuthoritiesIsTheMinimalEntry()
    {
        var e = SingleEntry(Fx.List(Fx.Allow(Fx.SidOf(1, 5))));

        Assert.Equal(16, e.DeclaredSize);
        Assert.Equal("S-1-5", e.Trailer.ToCanonicalString());
    }
}
