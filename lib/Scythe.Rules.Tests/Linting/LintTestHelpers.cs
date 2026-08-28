using Scythe.Rules.Linting;

namespace Scythe.Rules.Tests.Linting;

internal static class LintTestHelpers
{
    public const string FileName = "rules.json";

    public static LintResult Lint(string json, LintOptions? options = null) =>
        RuleFileLinter.Lint(json, FileName, options);

    public static IReadOnlyList<LintFinding> WithCode(this LintResult result, LintCode code) =>
        result.Findings.Where(f => f.Code == code).ToList();

    public static LintFinding Single(this LintResult result, LintCode code) =>
        Xunit.Assert.Single(result.WithCode(code));

    public static void AssertNone(this LintResult result, LintCode code) =>
        Xunit.Assert.Empty(result.WithCode(code));
}
