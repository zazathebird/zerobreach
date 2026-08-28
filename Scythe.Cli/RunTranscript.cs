using System.Text;

namespace Scythe.Cli;

/// <summary>
/// `--log &lt;path&gt;`: tees everything the engine writes to the console into a plain-text
/// file, so a run leaves a readable transcript beside its reports.
///
/// It works by replacing <see cref="Console.Out"/> and <see cref="Console.Error"/> rather
/// than by threading a writer through the scan: console output comes from
/// <see cref="ConsoleScanLogger"/>, from <c>Program</c> directly, and from the interactive
/// remediation session, and a transcript that quietly missed one of those would be worse
/// than none. Colour is applied through <see cref="Console.ForegroundColor"/>, never as
/// ANSI escapes, so the file is clean text with no filtering needed.
///
/// stdout and stderr share ONE synchronized file writer, so an error lands in the
/// transcript in the position it actually occurred — the failure case is the main reason
/// to read one of these.
/// </summary>
public sealed class RunTranscript : IDisposable
{
    private readonly TextWriter _file;
    private readonly TextWriter _prevOut;
    private readonly TextWriter _prevError;

    private RunTranscript(TextWriter file, TextWriter prevOut, TextWriter prevError)
    {
        _file = file;
        _prevOut = prevOut;
        _prevError = prevError;
    }

    /// <summary>
    /// Opens <paramref name="path"/> and redirects the console into it. Throws
    /// <see cref="IOException"/> if the file cannot be opened — the caller reports that and
    /// exits, because discovering an unwritable transcript path after a 40-minute DEEP scan
    /// is discovering it too late.
    /// </summary>
    public static RunTranscript Start(string path, string version, string[] args)
    {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // AutoFlush: a scan that is cancelled, crashes or is killed at the console must
        // still leave a complete transcript up to that point. Buffering would lose exactly
        // the tail that explains what happened.
        var file = new StreamWriter(
            new FileStream(full, FileMode.Create, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true))
        { AutoFlush = true };
        var sync = TextWriter.Synchronized(file);

        // Provenance header: a transcript that does not say which build produced it, on
        // which machine, from which command line is a much weaker IR artifact.
        sync.WriteLine($"# Scythe {version} — console transcript");
        sync.WriteLine($"# started : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sync.WriteLine($"# machine : {Environment.MachineName}");
        sync.WriteLine($"# command : scythescan {string.Join(" ", args)}");
        sync.WriteLine();

        var prevOut = Console.Out;
        var prevError = Console.Error;
        Console.SetOut(new TeeWriter(prevOut, sync));
        Console.SetError(new TeeWriter(prevError, sync));
        return new RunTranscript(sync, prevOut, prevError);
    }

    public void Dispose()
    {
        Console.SetOut(_prevOut);
        Console.SetError(_prevError);
        _file.WriteLine();
        _file.WriteLine($"# finished: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        _file.Dispose();
    }

    /// <summary>Writes every call through to both the real console and the file.</summary>
    private sealed class TeeWriter : TextWriter
    {
        private readonly TextWriter _console;
        private readonly TextWriter _file;

        public TeeWriter(TextWriter console, TextWriter file)
        {
            _console = console;
            _file = file;
        }

        public override Encoding Encoding => _console.Encoding;

        // Only the primitives are overridden. Every other TextWriter.Write/WriteLine
        // overload funnels into these, so the tee cannot be bypassed by one that was
        // forgotten here.
        public override void Write(char value)
        {
            _console.Write(value);
            _file.Write(value);
        }

        public override void Write(string? value)
        {
            _console.Write(value);
            _file.Write(value);
        }

        public override void Write(char[] buffer, int index, int count)
        {
            _console.Write(buffer, index, count);
            _file.Write(buffer, index, count);
        }

        public override void Flush()
        {
            _console.Flush();
            _file.Flush();
        }
    }
}
