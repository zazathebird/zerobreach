using Xunit;

// The suite is small and several tests time budget behaviour; serialising them keeps a
// deadline canary from being starved by a parallel collection and going red for the wrong reason.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
