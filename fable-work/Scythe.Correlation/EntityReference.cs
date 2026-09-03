using System.Globalization;

namespace Scythe.Correlation;

/// <summary>
/// A typed but not yet normalised reference to an entity — the projection of a finding's typed
/// target. The caller maps the record model's <c>FindingTarget</c> onto this: the kind says what
/// the check asserted the target is, and <see cref="Value"/> is the text as the check wrote it.
/// </summary>
/// <remarks>
/// This is deliberately not a copy of the record model, which is owned by <c>Scythe.Reporting</c>
/// and may not be declared elsewhere (reference/07_records.md). It is the two facts this library
/// needs from a target and nothing more.
/// </remarks>
public sealed record EntityReference(EntityKind Kind, string Value)
{
    public static EntityReference Path(string value) => new(EntityKind.Path, value);

    public static EntityReference RegistryPath(string value) => new(EntityKind.RegistryPath, value);

    /// <summary>Only meaningful within one run record; see <see cref="EntityKind.ProcessId"/>.</summary>
    public static EntityReference ProcessId(int value) =>
        new(EntityKind.ProcessId, value.ToString(CultureInfo.InvariantCulture));

    public static EntityReference HostName(string value) => new(EntityKind.HostName, value);

    public static EntityReference NetworkPeer(string value) => new(EntityKind.NetworkPeer, value);
}
