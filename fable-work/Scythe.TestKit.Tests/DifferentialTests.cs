using System.Reflection;
using Scythe.TestKit;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Scythe.TestKit.Tests;

/// <summary>
/// The rule that matters more than the rest of the runner: an absent reference tool is a
/// visible skip, never a pass. Proven three ways here — at the probe, at the runner's result,
/// and through xUnit's own message pipeline.
/// </summary>
public sealed class DifferentialTests
{
    private const string NoSuchTool = "scythe-no-such-tool-7f3a";
    private const string NoSuchPath = "/nonexistent/scythe/" + NoSuchTool;

    private static readonly string OwnAssemblyFile = Path.GetFileName(typeof(DifferentialTests).Assembly.Location);

    private static ToolProbe Absent() => ExternalTool.Find(NoSuchTool, new[] { NoSuchPath }, searchPath: string.Empty);

    // ---- the probe --------------------------------------------------------------------------

    [Fact]
    public void AnAbsentToolIsNotFoundAndTheReasonNamesToolAndPlacesLookedAt()
    {
        var probe = Absent();

        Assert.False(probe.Found);
        Assert.Null(probe.Path);
        Assert.Contains($"reference tool '{NoSuchTool}' not found", probe.Reason, StringComparison.Ordinal);
        Assert.Contains(NoSuchPath, probe.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void WithNothingToLookAtTheReasonSaysSo()
    {
        var probe = ExternalTool.Find(NoSuchTool, null, string.Empty);

        Assert.False(probe.Found);
        Assert.Contains("nowhere", probe.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AToolOnTheSearchPathIsFound()
    {
        var probe = ExternalTool.Find(OwnAssemblyFile, null, searchPath: AppContext.BaseDirectory);

        Assert.True(probe.Found);
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, OwnAssemblyFile), probe.Path);
        Assert.Contains("found at", probe.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void CandidatesAreTriedBeforeTheSearchPath()
    {
        string candidate = typeof(DifferentialTests).Assembly.Location;

        var probe = ExternalTool.Find(OwnAssemblyFile, new[] { NoSuchPath, candidate }, searchPath: AppContext.BaseDirectory);

        Assert.True(probe.Found);
        Assert.Equal(candidate, probe.Path);
    }

    [Fact]
    public void AnEmptyToolNameIsAnError()
    {
        Assert.Throws<FixtureException>(() => ExternalTool.Find(string.Empty));
    }

    // ---- the runner's result ----------------------------------------------------------------

    [Fact]
    public void RunningAnAbsentToolIsIncompleteWithTheReasonAndNeverCompares()
    {
        bool compared = false;

        var result = DifferentialRunner.Run(Absent(), new[] { "--version" }, null, _ => { compared = true; return null; });

        Assert.Equal(KitResultState.Incomplete, result.State);
        Assert.False(result.IsOk);
        Assert.Null(result.Value);
        Assert.StartsWith("skipped: reference tool '" + NoSuchTool, result.Reason, StringComparison.Ordinal);
        Assert.False(compared);
    }

    [Fact]
    public void AProbeThatLiesAboutItsPathIsFailedNotOk()
    {
        var lying = new ToolProbe(NoSuchTool, true, NoSuchPath, "planted");

        var result = DifferentialRunner.Run(lying, Array.Empty<string>(), null, _ => null);

        Assert.Equal(KitResultState.Failed, result.State);
        Assert.Contains("could not start", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireOnAnAbsentProbeThrowsTheSkipExceptionWithTheReason()
    {
        var probe = Absent();

        var e = Assert.Throws<DifferentialSkipException>(() => Differential.Require(probe));

        Assert.Equal(probe.Reason, e.Message);
    }

    [Fact]
    public void RequireOnAFoundProbeReturnsThePath()
    {
        var probe = ExternalTool.Find(OwnAssemblyFile, null, AppContext.BaseDirectory);

        Assert.Equal(probe.Path, Differential.Require(probe));
    }

    [Fact]
    public void RequireMapsTheThreeResultStatesToRunSkipAndFail()
    {
        var run = new ToolRun("/x", Array.Empty<string>(), 0, Array.Empty<byte>(), Array.Empty<byte>());

        Assert.Same(run, Differential.Require(KitResult<ToolRun>.Ok(run)));
        var skip = Assert.Throws<DifferentialSkipException>(() => Differential.Require(KitResult<ToolRun>.Incomplete(null, "skipped: absent")));
        Assert.Equal("skipped: absent", skip.Message);
        var fail = Assert.Throws<XunitException>(() => Differential.Require(KitResult<ToolRun>.Failed("disagrees: x")));
        Assert.Equal("disagrees: x", fail.Message);
    }

    // ---- a real skip, visible in the run's own output ---------------------------------------

    [DifferentialFact]
    public void ADifferentialFactWithAnAbsentToolShowsAsSkippedInThisRun()
    {
        // Deliberately points at a path that does not exist. In the test output this appears as
        // a skipped test with the reason, not as a pass — that is the whole point of the runner.
        Differential.Require(Absent());
        Assert.Fail("unreachable: Require must have skipped");
    }

    // ---- real invocations, through /bin/sh when this machine has one ------------------------

    private static ToolProbe Shell() => ExternalTool.Find("sh", new[] { "/bin/sh" });

    [DifferentialFact]
    public void AToolThatAgreesIsOkAndItsOutputIsCaptured()
    {
        var probe = Shell();
        Differential.Require(probe);

        var result = DifferentialRunner.Run(probe, new[] { "-c", "cat" }, "hello"u8.ToArray(), run =>
            run.StandardOutput.AsSpan().SequenceEqual("hello"u8) ? null : "stdout was not echoed");

        var run = Differential.Require(result);
        Assert.Equal(KitResultState.Ok, result.State);
        Assert.Equal(0, run.ExitCode);
        Assert.Equal("hello"u8.ToArray(), run.StandardOutput);
        Assert.Empty(run.StandardError);
        Assert.Equal(new[] { "-c", "cat" }, run.Arguments);
    }

    [DifferentialFact]
    public void AToolThatDisagreesIsFailedWithTheDifferenceAndExitCode()
    {
        var probe = Shell();
        Differential.Require(probe);

        var result = DifferentialRunner.Run(probe, new[] { "-c", "printf err 1>&2; exit 3" }, null, run =>
            run.StandardError.AsSpan().SequenceEqual("err"u8) ? "expected 4 records, tool printed 3" : "stderr missing");

        Assert.Equal(KitResultState.Failed, result.State);
        Assert.Contains("(exit 3) disagrees: expected 4 records, tool printed 3", result.Reason, StringComparison.Ordinal);
        Assert.Throws<XunitException>(() => Differential.Require(result));
    }

    [DifferentialFact]
    public void AToolThatOverrunsTheTimeoutIsIncompleteNotOk()
    {
        var probe = Shell();
        Differential.Require(probe);

        var result = DifferentialRunner.Run(probe, new[] { "-c", "sleep 5" }, null, _ => null, TimeSpan.FromMilliseconds(200));

        Assert.Equal(KitResultState.Incomplete, result.State);
        Assert.Contains("did not exit within 200 ms", result.Reason, StringComparison.Ordinal);
        Assert.Throws<DifferentialSkipException>(() => Differential.Require(result));
    }

    // ---- xUnit's pipeline: the failure-to-skip rewrite --------------------------------------

    private static (ITest Test, XunitTestCase Case) Subject(string method, bool differential)
    {
        var assembly = new TestAssembly(Reflector.Wrap(typeof(SkipSubject).Assembly));
        var collection = new TestCollection(assembly, null, "differential subjects");
        var testClass = new TestClass(collection, Reflector.Wrap(typeof(SkipSubject)));
        var testMethod = new TestMethod(testClass, Reflector.Wrap(typeof(SkipSubject).GetMethod(method)!));
        XunitTestCase testCase = differential
            ? new DifferentialTestCase(new NullMessageSink(), TestMethodDisplay.ClassAndMethod, TestMethodDisplayOptions.None, testMethod)
            : new XunitTestCase(new NullMessageSink(), TestMethodDisplay.ClassAndMethod, TestMethodDisplayOptions.None, testMethod);
        return (new XunitTest(testCase, testCase.DisplayName), testCase);
    }

    [Fact]
    public void TheBusRewritesASkipExceptionFailureIntoATestSkipped()
    {
        var (test, _) = Subject(nameof(SkipSubject.Skips), true);
        var inner = new CapturingBus();
        var bus = new SkipReportingMessageBus(inner);

        bus.QueueMessage(new TestFailed(test, 0m, string.Empty, new DifferentialSkipException("tool absent, looked at /nowhere")));

        var skipped = Assert.IsAssignableFrom<ITestSkipped>(Assert.Single(inner.Messages));
        Assert.Equal("tool absent, looked at /nowhere", skipped.Reason);
        Assert.Equal(1, bus.SkippedCount);
    }

    [Fact]
    public void TheBusPassesEveryOtherFailureAndMessageThrough()
    {
        var (test, _) = Subject(nameof(SkipSubject.Fails), true);
        var inner = new CapturingBus();
        var bus = new SkipReportingMessageBus(inner);

        bus.QueueMessage(new TestFailed(test, 0m, string.Empty, new InvalidOperationException("real failure")));
        bus.QueueMessage(new TestPassed(test, 0m, string.Empty));

        Assert.Equal(2, inner.Messages.Count);
        Assert.IsAssignableFrom<ITestFailed>(inner.Messages[0]);
        Assert.IsAssignableFrom<ITestPassed>(inner.Messages[1]);
        Assert.Equal(0, bus.SkippedCount);
    }

    [Fact]
    public async Task ADifferentialTestCaseReportsASkipAsSkippedNotFailed()
    {
        var (_, testCase) = Subject(nameof(SkipSubject.Skips), true);
        var bus = new CapturingBus();

        var summary = await testCase.RunAsync(new NullMessageSink(), bus, Array.Empty<object>(), new ExceptionAggregator(), new CancellationTokenSource());

        Assert.Equal(1, summary.Total);
        Assert.Equal(1, summary.Skipped);
        Assert.Equal(0, summary.Failed);
        var skipped = Assert.Single(bus.Messages.OfType<ITestSkipped>());
        Assert.Equal("the subject skipped on purpose", skipped.Reason);
        Assert.Empty(bus.Messages.OfType<ITestFailed>());
    }

    [Fact]
    public async Task ThePlainXunitTestCaseReportsTheSameSkipAsAFailure()
    {
        // The negative control: without the rewrite, the very same method is a failure. This is
        // what proves the differential test case is doing the work.
        var (_, testCase) = Subject(nameof(SkipSubject.Skips), false);
        var bus = new CapturingBus();

        var summary = await testCase.RunAsync(new NullMessageSink(), bus, Array.Empty<object>(), new ExceptionAggregator(), new CancellationTokenSource());

        Assert.Equal(1, summary.Failed);
        Assert.Equal(0, summary.Skipped);
    }

    [Fact]
    public async Task ADifferentialTestCaseStillFailsARealFailureAndPassesAPass()
    {
        var (_, failing) = Subject(nameof(SkipSubject.Fails), true);
        var (_, passing) = Subject(nameof(SkipSubject.Passes), true);

        var failed = await failing.RunAsync(new NullMessageSink(), new CapturingBus(), Array.Empty<object>(), new ExceptionAggregator(), new CancellationTokenSource());
        var passed = await passing.RunAsync(new NullMessageSink(), new CapturingBus(), Array.Empty<object>(), new ExceptionAggregator(), new CancellationTokenSource());

        Assert.Equal(1, failed.Failed);
        Assert.Equal(0, failed.Skipped);
        Assert.Equal(1, passed.Total);
        Assert.Equal(0, passed.Failed);
        Assert.Equal(0, passed.Skipped);
    }

    [Fact]
    public void TheDiscovererAttributeNamesTheRealDiscovererTypeAndAssembly()
    {
        // XunitTestCaseDiscovererAttribute takes strings, which can drift from the type they
        // name without a compile error. Pin them to the type.
        var data = typeof(DifferentialFactAttribute).GetCustomAttributesData()
            .Single(a => a.AttributeType == typeof(XunitTestCaseDiscovererAttribute));

        Assert.Equal(typeof(DifferentialFactDiscoverer).FullName, data.ConstructorArguments[0].Value);
        Assert.Equal(typeof(DifferentialFactDiscoverer).Assembly.GetName().Name, data.ConstructorArguments[1].Value);
    }

    [Fact]
    public void TheDiscovererYieldsADifferentialTestCase()
    {
        var (_, plain) = Subject(nameof(SkipSubject.Passes), false);
        var discoverer = new DifferentialFactDiscoverer(new NullMessageSink());
        var factData = typeof(SkipSubject).GetMethod(nameof(SkipSubject.Passes))!.GetCustomAttributesData().Single(a => a.AttributeType == typeof(FactAttribute));

        var cases = discoverer.Discover(new DefaultDiscoveryOptions(), plain.TestMethod, Reflector.Wrap(factData)).ToList();

        Assert.IsType<DifferentialTestCase>(Assert.Single(cases));
    }

    /// <summary>Discovery options with nothing set, so every accessor falls back to its default.</summary>
    private sealed class DefaultDiscoveryOptions : ITestFrameworkDiscoveryOptions
    {
        public TValue GetValue<TValue>(string name) => default!;

        public void SetValue<TValue>(string name, TValue value)
        {
        }
    }

    /// <summary>
    /// Deliberately not public, so xUnit's discovery never sees it (v2 discovers exported types
    /// only) and its failing method cannot fail the real run; the tests above run its methods
    /// in-process through the test-case machinery. The analyzer rule wants test classes public,
    /// which is exactly what this one must not be.
    /// </summary>
#pragma warning disable xUnit1000
    internal sealed class SkipSubject
    {
        [Fact]
        public void Skips() => Differential.Skip("the subject skipped on purpose");

        [Fact]
        public void Fails() => throw new InvalidOperationException("the subject failed on purpose");

        [Fact]
        public void Passes()
        {
        }
    }
#pragma warning restore xUnit1000

    private sealed class CapturingBus : IMessageBus
    {
        public List<IMessageSinkMessage> Messages { get; } = new();

        public bool QueueMessage(IMessageSinkMessage message)
        {
            Messages.Add(message);
            return true;
        }

        public void Dispose()
        {
        }
    }
}
