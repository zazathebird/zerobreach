namespace ZeroBreach.Remediation;

public static class ZbPaths
{
    /// <summary>Data root for the vault and action log: %ProgramData%\ZeroBreach, falling
    /// back to a folder beside the executable when ProgramData is unwritable.</summary>
    public static string DataRoot
    {
        get
        {
            var pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var root = Path.Combine(pd, "ZeroBreach");
            try
            {
                Directory.CreateDirectory(root);
                return root;
            }
            catch
            {
                var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
                var alt = Path.Combine(exeDir, "ZeroBreachData");
                Directory.CreateDirectory(alt);
                return alt;
            }
        }
    }

    public static string VaultDir => Path.Combine(DataRoot, "Vault");
    public static string ActionLogPath => Path.Combine(DataRoot, "action-log.jsonl");
}
