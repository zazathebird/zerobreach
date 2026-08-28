using System.Text;
using System.Text.Json;

namespace Scythe.Rules.Linting;

/// <summary>
/// Renders a <see cref="LintResult"/> for the two audiences the linter has: a technician
/// at a terminal (text) and a pipeline (JSON). Both renderings are deterministic — same
/// result, same bytes.
/// </summary>
public static class LintReport
{
    public static void WriteText(LintResult result, string fileName, TextWriter writer)
    {
        if (result.State == OperationState.Failed)
        {
            writer.WriteLine($"error: {result.Reason}");
            return;
        }

        foreach (var finding in result.Findings)
        {
            writer.WriteLine(finding.ToString());
        }

        writer.WriteLine(
            $"{fileName}: {Count(result, LintSeverity.Critical)} critical, " +
            $"{Count(result, LintSeverity.Error)} error(s), " +
            $"{Count(result, LintSeverity.Warning)} warning(s), " +
            $"{Count(result, LintSeverity.Info)} info");

        if (result.State == OperationState.Incomplete)
        {
            // Loud and last, so a truncated lint can never scroll past as a clean one.
            writer.WriteLine($"INCOMPLETE: {result.Reason}");
        }
    }

    public static void WriteJson(LintResult result, string fileName, TextWriter writer)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            json.WriteStartObject();
            json.WriteString("file", fileName);
            json.WriteString("state", result.State switch
            {
                OperationState.Ok => "ok",
                OperationState.Incomplete => "incomplete",
                _ => "failed",
            });
            json.WriteString("reason", result.Reason);

            json.WriteStartObject("counts");
            json.WriteNumber("critical", Count(result, LintSeverity.Critical));
            json.WriteNumber("error", Count(result, LintSeverity.Error));
            json.WriteNumber("warning", Count(result, LintSeverity.Warning));
            json.WriteNumber("info", Count(result, LintSeverity.Info));
            json.WriteEndObject();

            json.WriteStartArray("findings");
            foreach (var finding in result.Findings)
            {
                json.WriteStartObject();
                json.WriteString("code", finding.Code.ToString());
                json.WriteString("severity", finding.Severity switch
                {
                    LintSeverity.Critical => "critical",
                    LintSeverity.Error => "error",
                    LintSeverity.Warning => "warning",
                    _ => "info",
                });
                json.WriteNumber("line", finding.Location.Line);
                json.WriteNumber("column", finding.Location.Column);
                json.WriteString("set", finding.SetName);
                json.WriteString("entry", finding.Entry);
                json.WriteString("message", finding.Message);
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteEndObject();
        }
        writer.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
    }

    private static int Count(LintResult result, LintSeverity severity)
    {
        int count = 0;
        foreach (var finding in result.Findings)
        {
            if (finding.Severity == severity)
            {
                count++;
            }
        }
        return count;
    }
}
