using Xunit;

// The suite is small and several tests measure budget behaviour (deadline, entry ceilings) that
// is easier to reason about without another collection competing for the same clock. Matches the
// convention of the other Scythe test projects.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
