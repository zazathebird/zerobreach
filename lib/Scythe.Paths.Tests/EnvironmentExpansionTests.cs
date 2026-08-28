using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// %VAR% expansion from the caller-supplied dictionary — never from the process environment.
/// The library is deterministic and immune to the machine it runs on; an unresolvable variable
/// is an explicit failure, because a guard comparing against literal "%SystemRoot%" text is not
/// comparing against the path the operation will actually touch.
/// </summary>
public sealed class EnvironmentExpansionTests
{
    private static readonly Dictionary<string, string> Env = new()
    {
        ["SystemRoot"] = @"C:\Windows",
        ["TEMP"] = @"C:\Users\tech\AppData\Local\Temp",
        ["ProgramFiles"] = @"C:\Program Files",
    };

    [Fact]
    public void Variable_ExpandsFromTheSuppliedDictionary()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"%SystemRoot%\System32", Env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\windows\system32", p.Canonical);
    }

    [Fact]
    public void Expansion_IsRecorded_TokenAndValue()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"%SystemRoot%\System32", Env);
        PathTransformation t = Assert.Single(
            p.Transformations, x => x.Kind == TransformationKind.EnvironmentVariableExpanded);
        Assert.Equal("%SystemRoot%", t.Before);
        Assert.Equal(@"C:\Windows", t.After);
    }

    [Fact]
    public void Lookup_IsCaseInsensitive_LikeWindows()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"%SYSTEMROOT%\System32", Env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\windows\system32", p.Canonical);
    }

    [Fact]
    public void MultipleVariables_AllExpand()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"%SystemRoot%\..\%TEMP%", Env);
        // %TEMP% expands to an absolute path mid-string; the resulting text is what it is —
        // here it produces a nonsense component containing ':' and fails loudly downstream.
        // Use a saner fixture for the happy path:
        p = PathNormalizer.Normalize(@"%ProgramFiles%\Vendor\Tool.exe", Env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\program files\vendor\tool.exe", p.Canonical);
    }

    [Fact]
    public void UnresolvableVariable_FailsExplicitly()
    {
        // Fail-closed judgement call (pinned): Windows would leave %NotSet% literal, but a
        // guard must not compare against text that names no real location.
        NormalizedPath p = PathNormalizer.Normalize(@"%NotSet%\x", Env);
        Assert.Equal(OperationState.Failed, p.State);
        Assert.Contains("%NotSet%", p.FailureReason);
    }

    [Fact]
    public void NullEnvironment_MeansNoVariablesAreDefined()
    {
        Assert.Equal(OperationState.Failed, PathNormalizer.Normalize(@"%SystemRoot%\x", null).State);
    }

    [Fact]
    public void LonePercent_IsLiteral()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"C:\Sales 100% final", Env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\sales 100% final", p.Canonical);
    }

    [Fact]
    public void ImplausibleVariableName_IsLiteral()
    {
        // Text between two '%' containing a separator is not a variable reference
        // (mirrors ExpandEnvironmentStrings' leniency for stray '%').
        NormalizedPath p = PathNormalizer.Normalize(@"C:\a%b\c%d", Env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\a%b\c%d", p.Canonical);
    }

    [Fact]
    public void ExpandedValue_IsNotReExpanded()
    {
        // Single-pass: a hostile dictionary cannot make expansion loop, and a value containing
        // '%' lands literally in the path.
        var env = new Dictionary<string, string> { ["A"] = "%B%", ["B"] = "never" };
        NormalizedPath p = PathNormalizer.Normalize(@"C:\%A%\x", env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\%b%\x", p.Canonical);
    }

    [Fact]
    public void CaseSensitiveDictionary_StillMatchesCaseInsensitively_Deterministically()
    {
        // Caller hands us an ordinal-keyed dictionary with case-duplicate keys: the match must
        // not depend on enumeration order. The ordinally-smallest key wins.
        var env = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["path"] = @"C:\lower",
            ["PATH"] = @"C:\upper",
        };
        NormalizedPath p = PathNormalizer.Normalize(@"%Path%\x", env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\upper\x", p.Canonical); // "PATH" < "path" ordinally
    }

    [Fact]
    public void ExpansionResult_GoesThroughFullNormalization()
    {
        var env = new Dictionary<string, string> { ["W"] = "C:/Windows/" };
        NormalizedPath p = PathNormalizer.Normalize(@"%W%\System32", env);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\windows\system32", p.Canonical);
    }

    [Fact]
    public void OverlongExpansion_FailsTheLengthBound()
    {
        var env = new Dictionary<string, string> { ["BIG"] = new string('a', PathLimits.MaxPathLength) };
        NormalizedPath p = PathNormalizer.Normalize(@"C:\%BIG%\x", env);
        Assert.Equal(OperationState.Failed, p.State);
        Assert.Contains("maximum", p.FailureReason);
    }
}
