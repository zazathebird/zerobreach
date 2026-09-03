using Scythe.TestKit;

namespace Scythe.TestKit.Tests;

/// <summary>
/// The known buffer the mutation tests work on. Layout, all little-endian, 30 bytes:
/// <code>
///  0.. 4  "HDR!"                 (header)
///  4.. 8  total_len   u32 = 30   (header)
///  8..12  root_off    u32 = 18   (header)
/// 12..14  count       u16 = 3    (header)
/// 14..18  header.crc32           (header, computed with its own slot as zero)
/// 18..22  child_off   u32 = 22   (root)
/// 22..23  cell_size   u8  = 5    (root/child)
/// 23..27  01 02 03 04            (root/child)
/// 27..30  00 00 00               (tail)
/// </code>
/// </summary>
internal static class SampleFixture
{
    public const int Length = 30;

    public static Fixture Build()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Region("header", () =>
        {
            b.Ascii("HDR!");
            b.Placeholder("total_len", 4);
            b.Placeholder("root_off", 4);
            b.Field("count", 2, 3);
            b.Crc32("header");
        });
        b.ResolveToLength("total_len");
        b.ResolveToRegionStart("root_off", "root");
        b.Region("root", () =>
        {
            b.Placeholder("child_off", 4);
            b.ResolveToRegionStart("child_off", "child");
            b.Region("child", () =>
            {
                b.Field("cell_size", 1, 5);
                b.Raw(1, 2, 3, 4);
            });
        });
        b.Region("tail", () => b.Pad(3));
        return b.Build();
    }
}
