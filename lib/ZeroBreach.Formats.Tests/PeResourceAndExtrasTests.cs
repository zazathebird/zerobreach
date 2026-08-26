using ZeroBreach.Formats;
using ZeroBreach.Formats.Pe;
using Xunit;

namespace ZeroBreach.Formats.Tests;

/// <summary>Resource tree, TLS, debug/PDB, Rich header and certificate directory parsing.</summary>
public sealed class PeResourceAndExtrasTests
{
    private static readonly byte[] Code = { 0xC3, 0x90, 0x90, 0x90 };

    [Fact]
    public void ResourceTree_NamedAndIdEntries_AreDecodedWithDataLeaves()
    {
        byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        uint rsrcVa = b.AddResources(
            ResSpec.Dir(16u, // RT_VERSION
                ResSpec.Dir("CONFIG",
                    ResSpec.Leaf(1033u, payload, codePage: 1252))),
            ResSpec.Leaf("RAWBLOB", new byte[] { 1, 2, 3 }));
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var root = r.Image!.ResourceRoot!;
        Assert.Null(root.Name);
        Assert.Null(root.Id);
        Assert.Equal(2, root.Children.Count);

        // Named entries come before id entries at each level, per the on-disk table order.
        var rawBlob = root.Children[0];
        Assert.Equal("RAWBLOB", rawBlob.Name);
        Assert.NotNull(rawBlob.Data);
        Assert.Equal(3u, rawBlob.Data!.Size);

        var version = root.Children[1];
        Assert.Equal(16u, version.Id);
        Assert.Null(version.Data);
        var config = Assert.Single(version.Children);
        Assert.Equal("CONFIG", config.Name);
        var leaf = Assert.Single(config.Children);
        Assert.Equal(1033u, leaf.Id);
        Assert.Empty(leaf.Children);
        Assert.Equal((uint)payload.Length, leaf.Data!.Size);
        Assert.Equal(1252u, leaf.Data.CodePage);
        Assert.InRange(leaf.Data.Rva, rsrcVa, rsrcVa + 0x1000); // payload lives inside .rsrc
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TlsCallbacks_ArePresentAndListedAsStoredVas(bool pe32Plus)
    {
        var b = new PeFixtureBuilder(pe32Plus);
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        ulong cb1 = b.ImageBase + 0x1100, cb2 = b.ImageBase + 0x1200;
        b.AddTls(cb1, cb2);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var tls = r.Image!.Tls!;
        Assert.True(tls.Present);
        Assert.Equal(new[] { cb1, cb2 }, tls.CallbackAddresses); // VAs as stored, not RVAs
        Assert.True(r.Metrics!.TlsCallbacksPresent);
        Assert.Equal(2, r.Metrics!.TlsCallbackCount);
    }

    [Fact]
    public void Tls_WithNoCallbacks_IsPresentButNotFlaggedInMetrics()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddTls(); // directory present, empty callback array
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        Assert.True(r.Image!.Tls!.Present);
        Assert.Empty(r.Image!.Tls!.CallbackAddresses);
        Assert.False(r.Metrics!.TlsCallbacksPresent);
        Assert.Equal(0, r.Metrics!.TlsCallbackCount);
    }

    [Fact]
    public void DebugDirectory_RsdsRecord_YieldsGuidAgeAndPdbPath()
    {
        var guid = new Guid("a1b2c3d4-e5f6-4789-8abc-def012345678");
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddDebug(guid, pdbAge: 3, pdbPath: @"C:\build\out\app.pdb");
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var entry = Assert.Single(r.Image!.DebugEntries);
        Assert.Equal(2u, entry.Type); // CodeView
        Assert.Equal(guid, entry.PdbGuid);
        Assert.Equal(3u, entry.PdbAge);
        Assert.Equal(@"C:\build\out\app.pdb", entry.PdbPath);
    }

    [Fact]
    public void RichHeader_IsDecodedWithXorKey()
    {
        var b = new PeFixtureBuilder();
        b.AddRichHeader((0x0105, 0x9E9F, 12), (0x0001, 0x0000, 3));
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var rich = r.Image!.RichHeader!;
        Assert.Equal(0x1234_5678u, rich.XorKey);
        Assert.Collection(rich.Entries,
            e =>
            {
                Assert.Equal((ushort)0x0105, e.ProductId);
                Assert.Equal((ushort)0x9E9F, e.BuildId);
                Assert.Equal(12u, e.Count);
            },
            e =>
            {
                Assert.Equal((ushort)0x0001, e.ProductId);
                Assert.Equal(3u, e.Count);
            });
    }

    [Fact]
    public void NoRichHeader_ReportsNull()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        Assert.Null(r.Image!.RichHeader);
    }

    [Fact]
    public void Certificate_PresenceOffsetSizeRecorded_AndBytesFetchedOnDemand()
    {
        byte[] cert = Enumerable.Range(0, 200).Select(i => (byte)(i * 7)).ToArray();
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddCertificate(cert);
        byte[] file = b.Build();
        var r = TestParse.Run(file);

        Assert.Equal(OperationState.Ok, r.State);
        var info = r.Image!.Certificate!;
        Assert.Equal((uint)cert.Length, info.Size);
        Assert.Equal(0u, info.Offset % 8); // certificate table is 8-aligned
        Assert.Equal(cert, PeParser.GetCertificateBytes(file, info));

        // The certificate lives past all mapped content, so a signed file reports an overlay.
        Assert.True(r.Metrics!.OverlayPresent);
    }

    [Fact]
    public void Certificate_RangePastEndOfFile_IsPresentButIncomplete_AndBytesAreNull()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetDirectory(4, 0x0100_0000, 0x200); // file offset far past EOF
        byte[] file = b.Build();
        var r = TestParse.Run(file);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("certificate directory") && x.Contains("past end of file"));
        var info = r.Image!.Certificate!;
        Assert.Equal(0x0100_0000u, info.Offset); // presence and claimed range still recorded
        Assert.Null(PeParser.GetCertificateBytes(file, info)); // but a lying range yields no bytes
    }
}
