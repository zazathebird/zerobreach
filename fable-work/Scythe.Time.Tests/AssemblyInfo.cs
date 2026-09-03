using Xunit;

// DeterminismTests mutates process-global state — CurrentCulture and, via the TZ variable, the
// host's local zone — because that is the only way to prove the library does not read either.
// xUnit runs collections in parallel by default, which would let those mutations leak into other
// tests mid-run. The suite is small enough that serialising it costs nothing worth having.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
