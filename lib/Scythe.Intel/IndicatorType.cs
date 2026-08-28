namespace Scythe.Intel;

/// <summary>The typed indicator kinds this layer normalises feeds into (BLUEPRINT §10).</summary>
public enum IndicatorType
{
    Sha256,
    Sha1,
    Md5,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Filename,
    FilePath,
    RegistryKey,
    Mutex,
    EmailAddress,
}
