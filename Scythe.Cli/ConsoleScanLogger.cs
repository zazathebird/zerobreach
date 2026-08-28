using System.Diagnostics;
using Scythe.Core.Model;
using Scythe.Core.Scanning;

namespace Scythe.Cli;

/// <summary>Live console progress (spec §7). STEALTH swaps in NullScanLogger instead of
/// this — nothing here needs a silent flag.</summary>
public sealed class ConsoleScanLogger : IScanLogger
{
    private readonly int _totalPhases;
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();

    public ConsoleScanLogger(int totalPhases) => _totalPhases = totalPhases;

    public void PhaseBanner(int phase, string name)
    {
        Console.WriteLine();
        WriteColored(ConsoleColor.Cyan,
            $"=== Phase {phase}/{_totalPhases}: {name} === (elapsed {_elapsed.Elapsed:hh\\:mm\\:ss})");
    }

    public void PhaseDone(int phase, string name, TimeSpan elapsed, int findings)
    {
        var color = findings > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
        WriteColored(color, $"    phase {phase} done in {elapsed.TotalSeconds:0.0}s — {findings} finding(s)");
    }

    public void Info(string message) => WriteColored(ConsoleColor.Gray, "    " + message);

    public void Warn(string message) => WriteColored(ConsoleColor.DarkYellow, "  ! " + message);

    public static void PrintFinding(Finding f)
    {
        var (color, tag) = f.Severity switch
        {
            Severity.Critical => (ConsoleColor.Red, "CRITICAL"),
            Severity.High => (ConsoleColor.DarkRed, "HIGH    "),
            Severity.Possible => (ConsoleColor.Yellow, "POSSIBLE"),
            _ => (ConsoleColor.DarkGray, "INFO    "),
        };
        Console.Write("  [");
        WriteColoredInline(color, tag);
        Console.Write("] ");
        Console.Write(f.Description);
        if (f.VendorTrusted) WriteColoredInline(ConsoleColor.Green, " [vendor-trusted]");
        Console.WriteLine();
        WriteColored(ConsoleColor.DarkGray, $"             {f.Target}");
    }

    private static void WriteColored(ConsoleColor color, string line)
    {
        WriteColoredInline(color, line);
        Console.WriteLine();
    }

    private static void WriteColoredInline(ConsoleColor color, string text)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = prev;
    }
}
