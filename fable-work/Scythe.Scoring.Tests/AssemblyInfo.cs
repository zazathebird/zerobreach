using Xunit;

// Kept serial to match the rest of the package. Nothing here mutates process-global state, but
// the determinism suite compares serialised output across runs and a serial run keeps any
// failure it reports attributable to one test rather than to interleaving.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
