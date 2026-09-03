namespace Scythe.Correlation;

/// <summary>
/// A typed target that did not normalise as the kind it claimed. Reported rather than dropped, so
/// that "this finding has no target entity" and "this finding's target was unreadable" stay
/// distinguishable.
/// </summary>
public sealed record RejectedTarget(string FindingId, EntityKind Kind, string Text, string Message);
