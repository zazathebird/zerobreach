using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Scythe.Rules.Tests.Yara;

/// <summary>
/// Locates the reference <c>yara</c> CLI, and turns "the binary is missing" from a silent
/// pass into a decision the caller has to make.
/// </summary>
/// <remarks>
/// The differential tests are the strongest correctness evidence this library has: they run
/// every fixture through both engines and compare match offsets and rule verdicts. When the
/// reference binary is absent they early-return, which means that on a machine without it —
/// a fresh CI runner, a container — those tests pass while testing nothing at all, and
/// nothing says so. A green suite that silently stopped checking the thing it exists to check
/// is worse than a red one.
///
/// xunit 2.6 has no <c>Assert.Skip</c> (that arrived in v3) and adding a package for it is a
/// dependency change this project does not need. So the skip stays, and
/// <see cref="AssertOptional"/> makes it explicit: set <c>SCYTHE_REQUIRE_YARA=1</c> and a
/// missing binary FAILS instead of passing. Set it in CI and on the release checklist; leave
/// it unset on a dev box that has not installed yara.
/// </remarks>
internal static class ReferenceYara
{
    /// <summary>Path to the reference CLI, or null when it is not installed.</summary>
    internal static readonly string? Path =
        new[] { "/usr/bin/yara", "/usr/local/bin/yara" }.FirstOrDefault(File.Exists);

    /// <summary>Name of the environment variable that makes the reference binary mandatory.</summary>
    internal const string RequireVariable = "SCYTHE_REQUIRE_YARA";

    /// <summary>
    /// Call from the <c>Path is null</c> branch, immediately before returning. Passes quietly
    /// unless the caller has declared the reference binary mandatory, in which case it fails
    /// with an actionable message rather than letting the test pass vacuously.
    /// </summary>
    internal static void AssertOptional()
    {
        string? require = Environment.GetEnvironmentVariable(RequireVariable);
        if (string.IsNullOrEmpty(require) || require == "0")
        {
            return;
        }

        Assert.Fail(
            $"{RequireVariable} is set, but the reference yara CLI was not found at " +
            "/usr/bin/yara or /usr/local/bin/yara. The differential tests would otherwise " +
            "have passed without comparing anything. Install yara, or unset " +
            $"{RequireVariable} to accept an unverified run.");
    }
}
