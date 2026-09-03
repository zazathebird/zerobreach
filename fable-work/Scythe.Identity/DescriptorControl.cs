namespace Scythe.Identity;

/// <summary>The descriptor control word. reference/11.3 §11.3, control flags.</summary>
[Flags]
public enum DescriptorControl : ushort
{
    None = 0,
    OwnerDefaulted = 0x0001,
    GroupDefaulted = 0x0002,
    DiscretionaryListPresent = 0x0004,
    DiscretionaryListDefaulted = 0x0008,
    SystemListPresent = 0x0010,
    SystemListDefaulted = 0x0020,
    DiscretionaryAutoInheritRequested = 0x0100,
    SystemAutoInheritRequested = 0x0200,
    DiscretionaryAutoInherited = 0x0400,
    SystemAutoInherited = 0x0800,
    DiscretionaryProtected = 0x1000,
    SystemProtected = 0x2000,
    ResourceManagerControlValid = 0x4000,
    SelfRelative = 0x8000,
}
