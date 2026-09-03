using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Scythe.TestKit;

/// <summary>Thrown by <see cref="Differential.Skip"/>; a <see cref="DifferentialFactAttribute"/> test reports it as a skip, not a failure and never a pass.</summary>
public sealed class DifferentialSkipException : Exception
{
    public DifferentialSkipException(string reason)
        : base(reason)
    {
    }
}

/// <summary>Entry points a differential test calls to turn "the reference tool is absent" into a visible skip.</summary>
public static class Differential
{
    public static void Skip(string reason) => throw new DifferentialSkipException(reason);

    /// <summary>The tool's path, or a skip naming where it was looked for.</summary>
    public static string Require(ToolProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        if (!probe.Found || probe.Path is null)
        {
            Skip(probe.Reason);
        }

        return probe.Path!;
    }

    /// <summary>
    /// The completed run for <c>Ok</c>; a skip for <c>Incomplete</c> (tool absent or timed out);
    /// an xUnit failure carrying the difference for <c>Failed</c>.
    /// </summary>
    public static ToolRun Require(KitResult<ToolRun> result)
    {
        ArgumentNullException.ThrowIfNull(result);
        switch (result.State)
        {
            case KitResultState.Ok:
                return result.Value!;
            case KitResultState.Incomplete:
                Skip(result.Reason ?? "differential run did not complete");
                return null!;
            default:
                throw new XunitException(result.Reason ?? "differential run failed");
        }
    }
}

/// <summary>
/// A <c>[Fact]</c> whose <see cref="DifferentialSkipException"/> is reported as a skipped test.
/// xUnit 2 has no dynamic skip of its own; this is the standard discoverer/test-case pattern,
/// implemented here because the package allows no packages beyond xUnit itself.
/// </summary>
[XunitTestCaseDiscoverer("Scythe.TestKit.DifferentialFactDiscoverer", "Scythe.TestKit")]
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class DifferentialFactAttribute : FactAttribute
{
}

public sealed class DifferentialFactDiscoverer : IXunitTestCaseDiscoverer
{
    private readonly IMessageSink diagnosticMessageSink;

    public DifferentialFactDiscoverer(IMessageSink diagnosticMessageSink)
    {
        this.diagnosticMessageSink = diagnosticMessageSink;
    }

    public IEnumerable<IXunitTestCase> Discover(ITestFrameworkDiscoveryOptions discoveryOptions, ITestMethod testMethod, IAttributeInfo factAttribute)
    {
        yield return new DifferentialTestCase(diagnosticMessageSink, discoveryOptions.MethodDisplayOrDefault(), discoveryOptions.MethodDisplayOptionsOrDefault(), testMethod);
    }
}

public sealed class DifferentialTestCase : XunitTestCase
{
    [Obsolete("Called by the de-serializer; should only be called by deriving classes for de-serialization purposes")]
    public DifferentialTestCase()
    {
    }

    public DifferentialTestCase(IMessageSink diagnosticMessageSink, TestMethodDisplay defaultMethodDisplay, TestMethodDisplayOptions defaultMethodDisplayOptions, ITestMethod testMethod, object[]? testMethodArguments = null)
        : base(diagnosticMessageSink, defaultMethodDisplay, defaultMethodDisplayOptions, testMethod, testMethodArguments)
    {
    }

    public override async Task<RunSummary> RunAsync(IMessageSink diagnosticMessageSink, IMessageBus messageBus, object[] constructorArguments, ExceptionAggregator aggregator, CancellationTokenSource cancellationTokenSource)
    {
        var bus = new SkipReportingMessageBus(messageBus);
        var summary = await base.RunAsync(diagnosticMessageSink, bus, constructorArguments, aggregator, cancellationTokenSource).ConfigureAwait(false);
        if (bus.SkippedCount > 0)
        {
            summary.Failed -= bus.SkippedCount;
            summary.Skipped += bus.SkippedCount;
        }

        return summary;
    }
}

/// <summary>
/// Rewrites a test failure whose exception is <see cref="DifferentialSkipException"/> into a
/// test-skipped message carrying the exception's reason. Every other message passes through.
/// </summary>
public sealed class SkipReportingMessageBus : IMessageBus
{
    private readonly IMessageBus inner;

    public SkipReportingMessageBus(IMessageBus inner)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public int SkippedCount { get; private set; }

    public bool QueueMessage(IMessageSinkMessage message)
    {
        if (message is ITestFailed failed
            && failed.ExceptionTypes.Length > 0
            && string.Equals(failed.ExceptionTypes[0], typeof(DifferentialSkipException).FullName, StringComparison.Ordinal))
        {
            SkippedCount++;
            string reason = failed.Messages.Length > 0 ? failed.Messages[0] : "skipped";
            return inner.QueueMessage(new TestSkipped(failed.Test, reason));
        }

        return inner.QueueMessage(message);
    }

    public void Dispose()
    {
        // The inner bus is owned by the runner that created it.
    }
}
