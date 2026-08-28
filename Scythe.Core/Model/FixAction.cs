namespace Scythe.Core.Model;

/// <summary>Suggested remediation action per spec §5.</summary>
public enum FixAction
{
    None = 0,
    DeleteFile,
    DeleteRegistryValue,
    KillProcess,
    Quarantine,

    /// <summary>A command for the operator to read and run BY HAND.
    /// The engine never executes a RunCommand fix_param (spec §3 shadow-copy rule, §6.8):
    /// it is display-only in every code path, including remediation batches.</summary>
    RunCommand,
}

public static class FixActionExtensions
{
    /// <summary>Destructive = changes machine state. RunCommand is listed destructive so it
    /// can never be auto-selected, even though the engine also refuses to execute it.</summary>
    public static bool IsDestructive(this FixAction a) => a != FixAction.None;

    /// <summary>Actions the remediation executor is allowed to perform at all.</summary>
    public static bool IsExecutable(this FixAction a) =>
        a is FixAction.DeleteFile or FixAction.DeleteRegistryValue or FixAction.KillProcess or FixAction.Quarantine;

    public static string ToWire(this FixAction a) => a switch
    {
        FixAction.None => "none",
        FixAction.DeleteFile => "delete_file",
        FixAction.DeleteRegistryValue => "delete_registry_value",
        FixAction.KillProcess => "kill_process",
        FixAction.Quarantine => "quarantine",
        FixAction.RunCommand => "run_command",
        _ => "none",
    };
}
