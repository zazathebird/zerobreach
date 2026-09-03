using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>Well-formed descriptors: owner, group, mixed discretionary list, both lists.</summary>
public sealed class DescriptorOrdinaryTests
{
    [Fact]
    public void OwnerGroupAndAThreeEntryDiscretionaryListDecode()
    {
        var d = Fx.Decode(Fx.Ordinary());

        Assert.Equal("S-1-5-32-544", d.Owner!.ToCanonicalString());
        Assert.Equal("S-1-5-18", d.Group!.ToCanonicalString());
        Assert.Equal(ListPresence.NotPresent, d.SystemList.Presence);

        var dacl = Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList);
        Assert.Equal(3, dacl.Items.Count);
        Assert.Equal(3, dacl.Header.DeclaredCount);
        Assert.Equal(0, dacl.Header.SurplusBytes);

        var e0 = Assert.IsType<AccessControlEntry.Decoded>(dacl.Items[0]);
        Assert.Equal(EntryType.AccessAllowed, e0.Type);
        Assert.Equal("S-1-1-0", e0.Trailer.ToCanonicalString());
        Assert.Equal(0x0012_00A9u, e0.Mask);
        Assert.Equal(EntryFlags.ObjectInherit | EntryFlags.ContainerInherit, e0.Flags);

        var e1 = Assert.IsType<AccessControlEntry.Decoded>(dacl.Items[1]);
        Assert.Equal(EntryType.AccessDenied, e1.Type);
        Assert.Equal("S-1-5-32-546", e1.Trailer.ToCanonicalString());

        var e2 = Assert.IsType<AccessControlEntry.Decoded>(dacl.Items[2]);
        Assert.Equal(EntryType.AccessAllowed, e2.Type);
        Assert.Equal("S-1-5-32-544", e2.Trailer.ToCanonicalString());
        Assert.Equal(0x001F_01FFu, e2.Mask);
    }

    [Fact]
    public void ADescriptorWithBothListsPresentDecodesBoth()
    {
        var builder = Fx.Ordinary();
        builder.SystemList = Fx.List(Fx.Audit(Fx.Everyone, 0x0001_0000, flags: 0xC0));
        var d = Fx.Decode(builder);

        var sacl = Assert.IsType<AccessControlList.Entries>(d.SystemList);
        var audit = Assert.IsType<AccessControlEntry.Decoded>(Assert.Single(sacl.Items));
        Assert.Equal(EntryType.SystemAudit, audit.Type);
        Assert.Equal(EntryFlags.SuccessfulAccessAudit | EntryFlags.FailedAccessAudit, audit.Flags);
        Assert.Equal(3, Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList).Items.Count);
        Assert.True(d.Control.HasFlag(DescriptorControl.SystemListPresent));
        Assert.True(d.Control.HasFlag(DescriptorControl.DiscretionaryListPresent));
    }

    [Fact]
    public void TheHeaderFieldsAreReportedAsRead()
    {
        var builder = Fx.Ordinary();
        builder.ExtraControl = 0x5001; // owner defaulted, discretionary protected, RM byte valid
        builder.ResourceManagerByte = 0x2A;
        var d = Fx.Decode(builder);

        Assert.Equal(1, d.Revision);
        Assert.Equal(DescriptorControl.SelfRelative | DescriptorControl.DiscretionaryListPresent
            | DescriptorControl.OwnerDefaulted | DescriptorControl.DiscretionaryProtected
            | DescriptorControl.ResourceManagerControlValid, d.Control);
        Assert.Equal(20u, d.Offsets.Owner);
        Assert.Equal(20u + 16, d.Offsets.Group);
        Assert.Equal(0u, d.Offsets.SystemList);
        Assert.Equal(20u + 16 + 12, d.Offsets.DiscretionaryList);
        Assert.Equal((byte)0x2A, d.ResourceManagerControl);
        Assert.Equal((byte)0x2A, d.ResourceManagerControlRaw);
    }

    [Fact]
    public void TheResourceManagerByteIsAbsentUnlessItsControlBitSaysOtherwise()
    {
        // Absent is not zero: the byte holds 0x2A but nothing says it means anything.
        var builder = Fx.Ordinary();
        builder.ResourceManagerByte = 0x2A;
        var d = Fx.Decode(builder);

        Assert.Null(d.ResourceManagerControl);
        Assert.Equal((byte)0x2A, d.ResourceManagerControlRaw);
    }

    [Fact]
    public void EntryOffsetsAreRelativeToTheDescriptorStart()
    {
        var d = Fx.Decode(Fx.Ordinary());
        var dacl = Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList);

        Assert.Equal(48, dacl.Header.Offset);
        Assert.Equal(56, dacl.Items[0].Offset);
        Assert.Equal(56 + 20, dacl.Items[1].Offset);
        Assert.Equal(56 + 20 + 24, dacl.Items[2].Offset);
    }

    [Fact]
    public void RightsAreDecodedUnderTheSuppliedKind()
    {
        var d = Fx.Decode(Fx.Ordinary(), ObjectKind.File);
        var e0 = (AccessControlEntry.Decoded)((AccessControlList.Entries)d.DiscretionaryList).Items[0];

        Assert.Equal(ObjectKind.File, d.MaskKind);
        Assert.Equal(MaskInterpretation.AccessRights, e0.MaskInterpretation);
        Assert.Equal(ObjectKind.File, e0.Rights!.Kind);
        Assert.Equal(new[] { "Read control", "Synchronize" }, e0.Rights.GenericAndStandardRights);
        Assert.Equal(new[] { "Read data", "Read extended attributes", "Execute", "Read attributes" }, e0.Rights.SpecificRights);
    }

    [Fact]
    public void WithoutAKindTheLowBitsStayRaw()
    {
        var d = Fx.Decode(Fx.Ordinary());
        var e0 = (AccessControlEntry.Decoded)((AccessControlList.Entries)d.DiscretionaryList).Items[0];

        Assert.Null(d.MaskKind);
        Assert.Null(e0.Rights!.SpecificRights);
        Assert.Equal(0x00A9, e0.Rights.SpecificRaw);
    }

    [Fact]
    public void BytesAfterTheLastStructureAreIgnored()
    {
        var builder = Fx.Ordinary();
        builder.TrailingBytes = 37;

        Assert.Equal(IdentityResultState.Ok, DescriptorDecoder.Decode(builder.Build()).State);
    }

    [Fact]
    public void StructureOrderInTheBufferDoesNotMatter()
    {
        var builder = Fx.Ordinary();
        builder.ListsFirst = true;
        var d = Fx.Decode(builder);

        Assert.Equal("S-1-5-32-544", d.Owner!.ToCanonicalString());
        Assert.Equal(3, Assert.IsType<AccessControlList.Entries>(d.DiscretionaryList).Items.Count);
        Assert.Equal(20u, d.Offsets.DiscretionaryList);
    }

    [Fact]
    public void OrdinaryEntriesCarryNoObjectTypesNoApplicationDataAndNoSurplus()
    {
        var d = Fx.Decode(Fx.Ordinary());
        foreach (var entry in ((AccessControlList.Entries)d.DiscretionaryList).Items.Cast<AccessControlEntry.Decoded>())
        {
            Assert.Null(entry.ObjectTypes);
            Assert.Null(entry.ApplicationData);
            Assert.Null(entry.LabelPolicy);
            Assert.Null(entry.IntegrityLevel);
            Assert.Equal(0, entry.SurplusBytes);
        }
    }
}
