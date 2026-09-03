using Xunit;

// The property harness measures wall-clock deadlines and per-thread allocation; both are
// noisier under parallel execution, and the package's other test projects disable it too.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
