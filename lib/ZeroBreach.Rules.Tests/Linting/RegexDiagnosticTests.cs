using ZeroBreach.Rules.Linting;
using Xunit;
using static ZeroBreach.Rules.Tests.Linting.LintTestHelpers;

namespace ZeroBreach.Rules.Tests.Linting;

public class RegexCompileTests
{
    [Fact]
    public void NonCompilingRegexIsAnErrorAtTheEntry()
    {
        var result = Lint("{\n\"s\": [\"unbalanced(paren\"]\n}");
        var finding = result.Single(LintCode.RegexDoesNotCompile);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Equal(2, finding.Location.Line);
        Assert.Equal("unbalanced(paren", finding.Entry);
        Assert.Contains("matches nothing", finding.Message);
    }

    [Fact]
    public void CompilingRegexProducesNoCompileFinding()
    {
        Lint("""{ "s": ["^valid_[a-z]{4,}$"] }""").AssertNone(LintCode.RegexDoesNotCompile);
    }
}

public class DoubleEscapeTests
{
    // In these fixtures the C# raw string holds the JSON text verbatim, so the
    // pattern the linter sees has each JSON "\\" collapsed to one backslash.

    [Fact]
    public void DoubleEscapedQuantifiedClassLetterFires()
    {
        // JSON "\\\\d+"  →  pattern \\d+  →  literal backslash then a quantified 'd'.
        var result = Lint("""{ "s": ["report\\\\d+\\.exe"] }""");
        var finding = result.Single(LintCode.DoubleEscapedClass);
        Assert.Equal(LintSeverity.Warning, finding.Severity);
        Assert.Contains("'d'", finding.Message);
        Assert.Contains("remove one escaping level", finding.Message);
    }

    [Fact]
    public void DoubleEscapedStandaloneClassLetterFires()
    {
        // JSON "^evil\\\\s$"  →  pattern ^evil\\s$  →  literal backslash, lone 's'.
        var result = Lint("""{ "s": ["^evil\\\\s$"] }""");
        Assert.Single(result.WithCode(LintCode.DoubleEscapedClass));
    }

    [Fact]
    public void ProperlyEscapedClassDoesNotFire()
    {
        // JSON "^report\\d+\\.exe$"  →  pattern ^report\d+\.exe$  →  a real \d.
        Lint("""{ "s": ["^report\\d+\\.exe$"] }""").AssertNone(LintCode.DoubleEscapedClass);
    }

    [Fact]
    public void PathComponentStartingWithAClassLetterDoesNotFire()
    {
        // \\data and \\bin are directory names, not mangled classes.
        Lint("""{ "s": ["^C:\\\\data\\\\bin\\\\evil\\.exe$"] }""")
            .AssertNone(LintCode.DoubleEscapedClass);
    }

    [Fact]
    public void TheBlueprintExampleAllowlistDoesNotFire()
    {
        Lint("""{ "fp_allowlists": { "a": ["^C:\\\\Program Files\\\\Vendor\\\\.*$"] } }""")
            .AssertNone(LintCode.DoubleEscapedClass);
    }

    [Fact]
    public void LiteralBackslashBeforeARealClassDoesNotFire()
    {
        // JSON "\\\\\\d{4}"  →  pattern \\\d{4}  →  literal backslash, then a real \d.
        Lint("""{ "s": ["build\\\\\\d{4}\\.dll"] }""").AssertNone(LintCode.DoubleEscapedClass);
    }

    [Fact]
    public void FiresEvenWhenThePatternDoesNotCompile()
    {
        // The text-level check must not hide behind the compile check.
        var result = Lint("""{ "s": ["(\\\\d+"] }""");
        Assert.Single(result.WithCode(LintCode.DoubleEscapedClass));
        Assert.Single(result.WithCode(LintCode.RegexDoesNotCompile));
    }
}
