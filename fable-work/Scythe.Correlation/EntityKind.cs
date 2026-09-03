namespace Scythe.Correlation;

/// <summary>
/// The kinds of thing a finding can name. reference/07.1_linking.md, table of kinds.
/// The declaration order is the sort order of entities in every output list.
/// </summary>
public enum EntityKind
{
    /// <summary>A file-system path in drive-letter or UNC form.</summary>
    Path,

    /// <summary>A registry key, or a registry value when a value name is present.</summary>
    RegistryPath,

    /// <summary>
    /// A process identifier. The operating system reuses identifiers over time, so a process
    /// identifier is only meaningful <b>within one run record</b>: two findings from different
    /// records that both name process 1234 are not talking about the same process, and nothing
    /// in this library must ever be used to say they are. <see cref="ChainBuilder.Build"/> takes
    /// the findings of exactly one record for this reason.
    /// </summary>
    ProcessId,

    /// <summary>A host name. Distinct from a literal address even when both denote one machine.</summary>
    HostName,

    /// <summary>
    /// A literal network address (IPv4 or IPv6). Distinct from a host name even when both denote
    /// one machine: the library has no resolver and does not pretend to.
    /// </summary>
    NetworkPeer,
}
