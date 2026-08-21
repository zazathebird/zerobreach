using System.Security.Cryptography;

namespace ZeroBreach.Core.Util;

public static class FileHasher
{
    /// <summary>SHA-256 of a file, lowercase hex; null when unreadable or larger than
    /// <paramref name="maxBytes"/> (hashing a multi-GB file mid-scan is a budget hole).</summary>
    public static string? Sha256(string path, long maxBytes = 128 * 1024 * 1024)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > maxBytes) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }
}
