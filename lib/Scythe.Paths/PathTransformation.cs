namespace Scythe.Paths;

/// <summary>The kind of rewrite normalisation applied. Every rewrite is recorded — a guard that silently rewrites its input cannot be audited.</summary>
public enum TransformationKind
{
    /// <summary>A <c>%VAR%</c> reference was replaced from the caller-supplied dictionary. Before/After are the token and its value.</summary>
    EnvironmentVariableExpanded,

    /// <summary>Forward slashes were rewritten to backslashes.</summary>
    SeparatorsNormalized,

    /// <summary>Runs of separators were collapsed to one (the leading UNC <c>\\</c> is not a run).</summary>
    DuplicateSeparatorsCollapsed,

    /// <summary>A <c>\\?\</c> / <c>\\.\</c> / <c>\\?\UNC\</c> prefix was rewritten to the comparison form.</summary>
    PrefixNormalized,

    /// <summary><c>.</c> segments were removed.</summary>
    DotSegmentsRemoved,

    /// <summary><c>..</c> segments were resolved against their parent.</summary>
    ParentSegmentsResolved,

    /// <summary>A <c>..</c> segment at the root was clamped (cannot climb above the root or above <c>\\server\share</c>).</summary>
    ParentTraversalClamped,

    /// <summary>Trailing dots/spaces were trimmed, as Windows does silently.</summary>
    TrailingDotsAndSpacesTrimmed,

    /// <summary>An alternate data stream suffix was split off the final component.</summary>
    AlternateDataStreamSplit,

    /// <summary>A trailing separator was removed.</summary>
    TrailingSeparatorRemoved,

    /// <summary>The comparison form was lower-cased (invariant). The display form keeps the original casing.</summary>
    CaseFolded,
}

/// <summary>
/// One recorded rewrite. <see cref="Before"/> and <see cref="After"/> are snapshots of the
/// whole path at the stage boundary, except <see cref="TransformationKind.EnvironmentVariableExpanded"/>,
/// where they are the <c>%VAR%</c> token and its replacement value.
/// </summary>
public sealed record PathTransformation(TransformationKind Kind, string Before, string After)
{
    public override string ToString() => $"{Kind}: \"{Before}\" -> \"{After}\"";
}
