using System;
using Xunit;

namespace Scythe.Rules.Tests.Yara;

/// <summary>
/// Tests the escape hatch itself. The differential tests early-return when the reference
/// binary is absent, so on a machine without it they pass while comparing nothing — and the
/// only thing standing between that and a falsely green suite is
/// <see cref="ReferenceYara.AssertOptional"/>. A guard nobody tests is a guard nobody has.
/// </summary>
public class ReferenceYaraTests
{
    private static void WithRequireVariable(string? value, Action body)
    {
        string? previous = Environment.GetEnvironmentVariable(ReferenceYara.RequireVariable);
        try
        {
            Environment.SetEnvironmentVariable(ReferenceYara.RequireVariable, value);
            body();
        }
        finally
        {
            Environment.SetEnvironmentVariable(ReferenceYara.RequireVariable, previous);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0")]
    public void AMissingReferenceBinaryIsToleratedByDefault(string? value)
    {
        // A dev box without yara installed must still get a green suite — otherwise the
        // first thing anyone does is delete the guard.
        WithRequireVariable(value, () => ReferenceYara.AssertOptional());
    }

    [Theory]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("yes")]
    public void DeclaringTheReferenceBinaryMandatoryTurnsAVacuousPassIntoAFailure(string value)
    {
        WithRequireVariable(value, () =>
        {
            var ex = Assert.ThrowsAny<Exception>(() => ReferenceYara.AssertOptional());
            Assert.Contains(ReferenceYara.RequireVariable, ex.Message);
            Assert.Contains("yara", ex.Message, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void TheResolvedPathIsEitherAbsentOrOneOfTheTwoKnownLocations()
    {
        if (ReferenceYara.Path is null)
        {
            return;
        }
        Assert.Contains(ReferenceYara.Path, new[] { "/usr/bin/yara", "/usr/local/bin/yara" });
    }
}
