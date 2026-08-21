using ZeroBreach.Core.Model;

namespace ZeroBreach.Tests;

internal static class TestHelpers
{
    public static Finding MakeFinding(
        Severity severity = Severity.High,
        FixAction fix = FixAction.None,
        string? fixParam = null,
        string target = @"C:\Users\victim\AppData\evil.exe",
        bool hashConfirmed = false,
        string group = "Test",
        string discriminator = "d") => new()
    {
        Id = Finding.ComputeId(group, target, discriminator),
        Severity = severity,
        Description = "test finding",
        Target = target,
        FixAction = fix,
        FixParam = fixParam,
        Group = group,
        HashConfirmed = hashConfirmed,
    };

    /// <summary>Fresh scratch directory under the test run's temp area.</summary>
    public static string NewScratchDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "zbtests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
