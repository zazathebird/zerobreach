using Xunit;

// Nothing here mutates process-global state, but the package convention is to serialise test
// collections so a suite that later needs to (culture, time zone) does not have to remember to.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
