namespace Scythe.Identity;

/// <summary>
/// Decodes an access mask. The high sixteen bits are named unconditionally; the low sixteen only
/// under a caller-supplied <see cref="ObjectKind"/>. reference/11.3 §11.3, the access mask.
/// </summary>
public static class AccessMaskDecoder
{
    // High half: bit → name. Table order is bit order so output order is deterministic.
    private static readonly (uint Bit, string Name)[] HighHalf =
    [
        (0x0001_0000, "Delete"),
        (0x0002_0000, "Read control"),
        (0x0004_0000, "Write discretionary list"),
        (0x0008_0000, "Write owner"),
        (0x0010_0000, "Synchronize"),
        (0x0100_0000, "Access system security"),
        (0x0200_0000, "Maximum allowed"),
        (0x1000_0000, "Generic all"),
        (0x2000_0000, "Generic execute"),
        (0x4000_0000, "Generic write"),
        (0x8000_0000, "Generic read"),
    ];

    // Low half, one sixteen-entry table per kind, index = bit number. Null = the table names
    // nothing for that bit under that kind. Sourced from the §11.3 table; the file/directory
    // column there carries two names per row separated by " / ", split here per kind.
    private static readonly string?[] FileRights =
    [
        "Read data", "Write data", "Append data", "Read extended attributes",
        "Write extended attributes", "Execute", "Delete child", "Read attributes",
        "Write attributes", null, null, null, null, null, null, null,
    ];

    private static readonly string?[] DirectoryRights =
    [
        "List contents", "Add file", "Add subdirectory", "Read extended attributes",
        "Write extended attributes", "Traverse", "Delete child", "Read attributes",
        "Write attributes", null, null, null, null, null, null, null,
    ];

    private static readonly string?[] RegistryKeyRights =
    [
        "Query value", "Set value", "Create subkey", "Enumerate subkeys",
        "Notify", "Create link", null, null,
        "Force 64-bit view", "Force 32-bit view", null, null, null, null, null, null,
    ];

    private static readonly string?[] ServiceRights =
    [
        "Query configuration", "Change configuration", "Query status", "Enumerate dependents",
        "Start", "Stop", "Pause and continue", "Interrogate",
        "User-defined control", null, null, null, null, null, null, null,
    ];

    private static readonly string?[] ProcessRights =
    [
        "Terminate", "Create thread", "Set session identifier", "Memory operation",
        "Memory read", "Memory write", "Duplicate handle", "Create process",
        "Set quota", "Set information", "Query information", "Suspend and resume",
        "Query limited information", null, null, null,
    ];

    public static DecodedAccessMask Decode(uint mask, ObjectKind? kind)
    {
        var high = new List<string>();
        uint named = 0;
        foreach (var (bit, name) in HighHalf)
        {
            if ((mask & bit) != 0)
            {
                high.Add(name);
                named |= bit;
            }
        }

        var specificRaw = (ushort)(mask & 0xFFFF);
        List<string>? specific = null;
        if (kind is { } k)
        {
            var table = TableFor(k);
            specific = new List<string>();
            for (var bit = 0; bit < 16; bit++)
            {
                var flag = 1u << bit;
                if ((mask & flag) == 0)
                {
                    continue;
                }

                if (table[bit] is { } name)
                {
                    specific.Add(name);
                    named |= flag;
                }
            }
        }
        else
        {
            // No kind: the low half is reported raw and is neither named nor counted as unnamed.
            // It is not that no name exists — it is that this call cannot know which one.
            named |= 0xFFFF;
        }

        var unnamed = mask & ~named;
        return new DecodedAccessMask(mask, kind, high, specificRaw, specific, unnamed);
    }

    private static string?[] TableFor(ObjectKind kind) => kind switch
    {
        ObjectKind.File => FileRights,
        ObjectKind.Directory => DirectoryRights,
        ObjectKind.RegistryKey => RegistryKeyRights,
        ObjectKind.Service => ServiceRights,
        ObjectKind.Process => ProcessRights,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "no rights table for this kind"),
    };
}
