using Xunit;

// DeterminismTests mutates process-global state — CurrentCulture — because that is the only way
// to prove the library does not read it. xUnit runs collections in parallel by default, which
// would let the mutation leak into other tests mid-run. The suite is small enough that
// serialising it costs nothing worth having. (Same rationale as Scythe.Time.Tests; see the Q1
// handoff entry for why named real cultures are useless here — InvariantGlobalization is on
// package-wide, so a hostile culture has to be a mutated clone of the invariant one.)
[assembly: CollectionBehavior(DisableTestParallelization = true)]
