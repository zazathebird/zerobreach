using ZeroBreach.Rules.Linting;
using Xunit;
using static ZeroBreach.Rules.Tests.Linting.LintTestHelpers;

namespace ZeroBreach.Rules.Tests.Linting;

public class DeterminismTests
{
    /// <summary>A file that trips many diagnostics at once, in no convenient order.</summary>
    private const string MessyFile =
        """
        {
          "empty_one": [],
          "short_ind": ["ab", "ab"],
          "collide": ["svchost"],
          "mangled": ["report\\\\d+"],
          "broken": ["oops(unclosed"],
          "fp_allowlists": {
            "wild": [".*"],
            "loose": ["C:\\\\temp\\\\.*"]
          },
          "references": { "phase": ["ghost_set", "collide"] }
        }
        """;

    [Fact]
    public void SameInputProducesIdenticalOutputTwice()
    {
        var first = Lint(MessyFile);
        var second = Lint(MessyFile);

        Assert.Equal(OperationState.Ok, first.State);
        Assert.Equal(first.Findings.Count, second.Findings.Count);
        for (int i = 0; i < first.Findings.Count; i++)
        {
            Assert.Equal(first.Findings[i], second.Findings[i]);
        }
    }

    [Fact]
    public void FindingsComeOutInFilePositionOrder()
    {
        var result = Lint(MessyFile);
        Assert.True(result.Findings.Count >= 8); // the file is genuinely messy

        for (int i = 1; i < result.Findings.Count; i++)
        {
            var prev = result.Findings[i - 1].Location;
            var next = result.Findings[i].Location;
            bool ordered = prev.Line < next.Line
                || (prev.Line == next.Line && prev.Column <= next.Column);
            Assert.True(ordered,
                $"finding {i} at {next} sorts before finding {i - 1} at {prev}");
        }
    }

    [Fact]
    public void TheRenderedReportsAreByteStable()
    {
        using var textA = new StringWriter();
        using var textB = new StringWriter();
        LintReport.WriteText(Lint(MessyFile), FileName, textA);
        LintReport.WriteText(Lint(MessyFile), FileName, textB);
        Assert.Equal(textA.ToString(), textB.ToString());

        using var jsonA = new StringWriter();
        using var jsonB = new StringWriter();
        LintReport.WriteJson(Lint(MessyFile), FileName, jsonA);
        LintReport.WriteJson(Lint(MessyFile), FileName, jsonB);
        Assert.Equal(jsonA.ToString(), jsonB.ToString());
    }
}
