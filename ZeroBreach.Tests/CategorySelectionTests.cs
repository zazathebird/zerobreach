using System.Reflection;
using ZeroBreach.Cli;
using ZeroBreach.Core.Scanning;

namespace ZeroBreach.Tests;

/// <summary>--only/--skip name validation runs against the REAL scanner list, so these
/// tests use the real ZeroBreach.Scanners assembly, not fakes.</summary>
public class CategorySelectionTests
{
    private static IReadOnlyList<IScanner> RealScanners() =>
        Assembly.Load(new AssemblyName("ZeroBreach.Scanners")).GetTypes()
            .Where(t => !t.IsAbstract && typeof(IScanner).IsAssignableFrom(t))
            .Select(t => (IScanner)Activator.CreateInstance(t)!)
            .ToList();

    [Fact]
    public void Skip_excludes_exactly_the_named_groups()
    {
        var excluded = CategorySelection.ComputeExcluded(RealScanners(),
            only: Array.Empty<string>(), skip: new[] { "EventLog", "ContentScan" }, out var error);
        Assert.Null(error);
        Assert.Equal(new[] { "EventLog", "ContentScan" }, excluded);
    }

    [Fact]
    public void Only_excludes_every_other_group()
    {
        var scanners = RealScanners();
        var excluded = CategorySelection.ComputeExcluded(scanners,
            only: new[] { "persistence", "c2" }, skip: Array.Empty<string>(), out var error);
        Assert.Null(error);
        Assert.NotNull(excluded);
        Assert.Equal(scanners.Count - 2, excluded!.Count);
        Assert.DoesNotContain("Persistence", excluded);
        Assert.DoesNotContain("C2", excluded);
        Assert.Contains("EventLog", excluded);
    }

    [Fact]
    public void Unknown_category_is_an_error_listing_the_valid_names()
    {
        var excluded = CategorySelection.ComputeExcluded(RealScanners(),
            only: Array.Empty<string>(), skip: new[] { "Persistnce" }, out var error);
        Assert.Null(excluded);
        Assert.NotNull(error);
        Assert.Contains("Persistnce", error);
        Assert.Contains("Persistence", error); // the valid list helps fix the typo
    }

    [Fact]
    public void No_selection_means_no_exclusions()
    {
        Assert.Null(CategorySelection.ComputeExcluded(RealScanners(),
            Array.Empty<string>(), Array.Empty<string>(), out var error));
        Assert.Null(error);
    }

    [Fact]
    public void Usage_text_lists_every_real_category_name()
    {
        // The --only/--skip help enumerates the categories; a new scanner must show up there.
        foreach (var s in RealScanners())
            Assert.Contains(s.Group, CliOptions.Usage);
    }
}
