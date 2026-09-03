using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>
/// The absence trio. Not-present grants everything; empty grants nothing; the two encodings of
/// not-present are kept apart. A revert to a possibly-empty collection fails all three.
/// </summary>
public sealed class DescriptorAbsenceTests
{
    private static AccessControlList ControlBitClear()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem };
        return Fx.Decode(b).DiscretionaryList;
    }

    private static AccessControlList ControlBitSetOffsetZero()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, ExtraControl = 0x0004 };
        return Fx.Decode(b).DiscretionaryList;
    }

    private static AccessControlList PresentWithCountZero()
    {
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, DiscretionaryList = Fx.List() };
        return Fx.Decode(b).DiscretionaryList;
    }

    [Fact]
    public void ControlBitClearIsNotPresent()
    {
        var list = Assert.IsType<AccessControlList.NotPresent>(ControlBitClear());

        Assert.Equal(ListPresence.NotPresent, list.Presence);
        Assert.Equal(AbsenceEncoding.ControlBitClear, list.Encoding);
        Assert.Equal(0u, list.IgnoredOffset);
    }

    [Fact]
    public void ControlBitSetWithZeroOffsetIsNotPresent()
    {
        var list = Assert.IsType<AccessControlList.NotPresent>(ControlBitSetOffsetZero());

        Assert.Equal(ListPresence.NotPresent, list.Presence);
        Assert.Equal(AbsenceEncoding.ControlBitSetOffsetZero, list.Encoding);
    }

    [Fact]
    public void PresentWithCountZeroIsEmpty()
    {
        var list = Assert.IsType<AccessControlList.Empty>(PresentWithCountZero());

        Assert.Equal(ListPresence.Empty, list.Presence);
        Assert.Equal(0, list.Header.DeclaredCount);
        Assert.Equal(8, list.Header.DeclaredSize);
        Assert.Equal(2, list.Header.Revision);
    }

    [Fact]
    public void AllThreeAreDistinguishableFromEachOther()
    {
        var clear = ControlBitClear();
        var zero = ControlBitSetOffsetZero();
        var empty = PresentWithCountZero();

        Assert.NotEqual(clear.Presence, empty.Presence);
        Assert.NotEqual(zero.Presence, empty.Presence);
        Assert.Equal(clear.Presence, zero.Presence);
        Assert.NotEqual(clear, zero);
        Assert.NotEqual(((AccessControlList.NotPresent)clear).Encoding, ((AccessControlList.NotPresent)zero).Encoding);
        Assert.IsNotType<AccessControlList.Entries>(clear);
        Assert.IsNotType<AccessControlList.Entries>(zero);
        Assert.IsNotType<AccessControlList.Entries>(empty);
    }

    [Fact]
    public void TheSystemListHasTheSameTrio()
    {
        var clear = Fx.Decode(new Fx.DescriptorBuilder { Owner = Fx.LocalSystem }).SystemList;
        var zero = Fx.Decode(new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, ExtraControl = 0x0010 }).SystemList;
        var empty = Fx.Decode(new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, SystemList = Fx.List() }).SystemList;

        Assert.Equal(AbsenceEncoding.ControlBitClear, Assert.IsType<AccessControlList.NotPresent>(clear).Encoding);
        Assert.Equal(AbsenceEncoding.ControlBitSetOffsetZero, Assert.IsType<AccessControlList.NotPresent>(zero).Encoding);
        Assert.IsType<AccessControlList.Empty>(empty);
    }

    [Fact]
    public void AClearControlBitIsAuthoritative_TheOffsetIsKeptButNotFollowed()
    {
        // The offset points at bytes that would fail as a list header (a bare identifier). Under
        // a clear bit the list is not present and the bytes are not read. Revert: follow any
        // nonzero offset, and this is Failed.
        var b = new Fx.DescriptorBuilder { Owner = Fx.LocalSystem, DiscretionaryList = Fx.SidOf(1, 0, 0), ControlOverride = 0x8000 };
        var d = Fx.Decode(b);

        var list = Assert.IsType<AccessControlList.NotPresent>(d.DiscretionaryList);
        Assert.Equal(AbsenceEncoding.ControlBitClear, list.Encoding);
        Assert.Equal(32u, list.IgnoredOffset);
    }

    [Fact]
    public void AnEmptyListWithSurplusInsideItsDeclaredSizeIsStillEmpty()
    {
        var b = new Fx.DescriptorBuilder { DiscretionaryList = Fx.List(2, Array.Empty<byte[]>(), padding: 8) };
        var list = Assert.IsType<AccessControlList.Empty>(Fx.Decode(b).DiscretionaryList);

        Assert.Equal(8, list.Header.SurplusBytes);
        Assert.Equal(16, list.Header.DeclaredSize);
    }

    [Fact]
    public void ADescriptorWithNothingPresentAtAllIsOk()
    {
        var d = Fx.Decode(new Fx.DescriptorBuilder());

        Assert.Null(d.Owner);
        Assert.Null(d.Group);
        Assert.Equal(ListPresence.NotPresent, d.SystemList.Presence);
        Assert.Equal(ListPresence.NotPresent, d.DiscretionaryList.Presence);
    }
}
