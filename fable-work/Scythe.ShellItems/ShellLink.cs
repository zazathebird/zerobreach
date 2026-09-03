namespace Scythe.ShellItems;

/// <summary>
/// One decoded shell link. On an <see cref="LinkResultState.Incomplete"/> result this carries the
/// sections read before the reader had to stop; <see cref="Length"/> says how far it got.
/// </summary>
public sealed record ShellLink(
    ShellLinkHeader Header,
    LinkTargetIdList? TargetIdList,
    LinkInfo? LinkInfo,
    LinkString? Name,
    LinkString? RelativePath,
    LinkString? WorkingDirectory,
    LinkString? Arguments,
    LinkString? IconLocation,
    IReadOnlyList<ExtraDataBlock> ExtraData,
    bool? TargetPathsDisagree,
    int Length,
    IReadOnlyList<string> Notes);
