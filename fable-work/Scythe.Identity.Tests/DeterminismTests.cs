using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>Same bytes, same output, same order — asserted rather than assumed.</summary>
public sealed class DeterminismTests
{
    private static Fx.DescriptorBuilder Rich()
    {
        var b = Fx.Ordinary();
        b.ResourceManagerByte = 7;
        b.ExtraControl = 0x4000;
        b.SystemList = Fx.List(4, new[]
        {
            Fx.ObjectEntry(0x07, 0xC0, 0x0001_0000, 3, new Guid("11111111-2222-3333-4444-555555555555"), new Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), Fx.Everyone),
            Fx.Entry(0x0D, 0x40, 1, Fx.LocalSystem, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }),
            Fx.Entry(0x11, 0, 3, Fx.MediumLabel),
            Fx.Entry(0x08, 0, 0xFFFF_FFFF, Fx.Administrators),
        });
        return b;
    }

    [Fact]
    public void TheSameBytesDecodedTwiceRenderByteIdentically()
    {
        var bytes = Rich().Build();

        var first = DescriptorDecoder.Decode(bytes, ObjectKind.RegistryKey);
        var second = DescriptorDecoder.Decode(bytes, ObjectKind.RegistryKey);

        Assert.Equal(first.State, second.State);
        Assert.Equal(first.Reason, second.Reason);
        Assert.Equal(Fx.Render(first.Value!), Fx.Render(second.Value!));
    }

    [Fact]
    public void TwoIndependentlyBuiltIdenticalBuffersRenderByteIdentically()
    {
        var a = DescriptorDecoder.Decode(Rich().Build(), ObjectKind.File).Value!;
        var b = DescriptorDecoder.Decode(Rich().Build(), ObjectKind.File).Value!;

        Assert.Equal(Fx.Render(a), Fx.Render(b));
    }

    [Fact]
    public void TheRenderingIsCompleteEnoughToSeeEveryField()
    {
        // Guards the determinism test against a renderer that drops fields: each of these must be
        // in the text, or an identical rendering proves less than it claims.
        var text = Fx.Render(DescriptorDecoder.Decode(Rich().Build(), ObjectKind.File).Value!);

        Assert.Contains("rm=7", text, StringComparison.Ordinal);
        Assert.Contains("owner=S-1-5-32-544", text, StringComparison.Ordinal);
        Assert.Contains("SystemAuditObject", text, StringComparison.Ordinal);
        Assert.Contains("11111111-2222-3333-4444-555555555555", text, StringComparison.Ordinal);
        Assert.Contains("appdata@", text, StringComparison.Ordinal);
        Assert.Contains("DEADBEEF", text, StringComparison.Ordinal);
        Assert.Contains("label=NoWriteUp, NoReadUp level=8192", text, StringComparison.Ordinal);
        Assert.Contains("unknown body@", text, StringComparison.Ordinal);
        Assert.Contains("Write data", text, StringComparison.Ordinal);
    }

    [Fact]
    public void EntriesComeBackInOnDiskOrder()
    {
        var d = DescriptorDecoder.Decode(Rich().Build()).Value!;
        var sacl = (AccessControlList.Entries)d.SystemList;

        Assert.Equal(new byte[] { 0x07, 0x0D, 0x11, 0x08 }, sacl.Items.Select(i => i.TypeByte));
        Assert.True(sacl.Items.Zip(sacl.Items.Skip(1)).All(p => p.First.Offset < p.Second.Offset));
    }

    [Fact]
    public void CanonicalStringsRoundTripThroughParseForEveryTableRowAndTheHexAuthority()
    {
        var samples = WellKnownIdentifiers.Entries
            .Select(WellKnownIdentifiers.ValueOf)
            .Where(v => v is not null)
            .Select(v => v!)
            .Append(Fx.Value(Fx.SidOf(1, 0x0100_0000_0005, 7)))
            .Append(Fx.Value(Fx.DomainAccount(uint.MaxValue)));

        foreach (var sid in samples)
        {
            var text = sid.ToCanonicalString();
            var parsed = Fx.Unwrap(IdentifierDecoder.Parse(text));
            Assert.True(parsed.WasCanonical, text);
            Assert.Equal(sid, parsed.Identifier);
            Assert.Equal(text, parsed.Identifier!.ToCanonicalString());
            Assert.Equal(sid.ToBytes(), Fx.Value(sid.ToBytes()).ToBytes());
        }
    }

    [Fact]
    public void TheWellKnownTableIsStableAcrossCalls()
    {
        var a = WellKnownIdentifiers.Entries.Select(e => $"{e.Pattern}|{e.Scope}|{e.Name}|{e.Abbreviation}").ToArray();
        var b = WellKnownIdentifiers.Entries.Select(e => $"{e.Pattern}|{e.Scope}|{e.Name}|{e.Abbreviation}").ToArray();

        Assert.Equal(a, b);
        Assert.Equal(a.Length, a.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ResultsForTheSameInputAreIndependentOfPreviousInputs()
    {
        // No static state leaks between decodes: a Failed decode first, then the good one.
        _ = DescriptorDecoder.Decode(new byte[20]);
        var afterBad = Fx.Render(DescriptorDecoder.Decode(Rich().Build()).Value!);
        var fresh = Fx.Render(DescriptorDecoder.Decode(Rich().Build()).Value!);

        Assert.Equal(fresh, afterBad);
    }
}
