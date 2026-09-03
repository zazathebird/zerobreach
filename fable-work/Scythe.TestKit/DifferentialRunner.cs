using System.Diagnostics;

namespace Scythe.TestKit;

/// <summary>One completed invocation of a reference tool.</summary>
public sealed record ToolRun(string Path, IReadOnlyList<string> Arguments, int ExitCode, byte[] StandardOutput, byte[] StandardError);

/// <summary>
/// Invokes a reference tool and compares its output with ours. Knows nothing about any tool:
/// the caller supplies the probe, the arguments, optional standard input and the comparison.
/// </summary>
/// <remarks>
/// Result states: <c>Ok</c> — the tool ran and the comparison found no difference;
/// <c>Incomplete</c> — the comparison did not happen, because the tool is absent or timed out,
/// with the reason saying which and where it was looked for (this is the state a test turns
/// into a visible skip); <c>Failed</c> — the tool could not be started, or it ran and the
/// comparison reported a difference, which is carried as the message.
/// </remarks>
public static class DifferentialRunner
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public static KitResult<ToolRun> Run(
        ToolProbe probe,
        IReadOnlyList<string> arguments,
        byte[]? standardInput,
        Func<ToolRun, string?> compare,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(compare);
        if (!probe.Found || probe.Path is null)
        {
            return KitResult<ToolRun>.Incomplete(null, "skipped: " + probe.Reason);
        }

        var info = new ProcessStartInfo(probe.Path)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        Process process;
        try
        {
            process = Process.Start(info) ?? throw new InvalidOperationException("Process.Start returned null");
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return KitResult<ToolRun>.Failed($"could not start '{probe.Path}': {e.Message}");
        }

        using (process)
        {
            var stdout = new MemoryStream();
            var stderr = new MemoryStream();
            var pumpOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
            var pumpErr = process.StandardError.BaseStream.CopyToAsync(stderr);
            try
            {
                if (standardInput is not null)
                {
                    process.StandardInput.BaseStream.Write(standardInput, 0, standardInput.Length);
                }

                process.StandardInput.Close();
            }
            catch (IOException)
            {
                // The tool closed its input early; whatever it printed still decides the outcome.
            }

            TimeSpan limit = timeout ?? DefaultTimeout;
            if (!process.WaitForExit((int)Math.Min(int.MaxValue, limit.TotalMilliseconds)))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // Already gone.
                }

                return KitResult<ToolRun>.Incomplete(null, $"skipped: '{probe.Path}' did not exit within {limit.TotalMilliseconds:0} ms and was killed; no comparison was made");
            }

            Task.WaitAll(pumpOut, pumpErr);
            var run = new ToolRun(probe.Path, arguments.ToList(), process.ExitCode, stdout.ToArray(), stderr.ToArray());
            string? difference = compare(run);
            return difference is null
                ? KitResult<ToolRun>.Ok(run)
                : KitResult<ToolRun>.Failed($"'{probe.Path}' (exit {run.ExitCode}) disagrees: {difference}");
        }
    }
}
