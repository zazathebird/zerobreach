using System.Net;
using System.Text;
using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Reporting;

/// <summary>Self-contained single-file HTML report for handing to a client (spec §7).</summary>
public static class HtmlReport
{
    public static void Write(string path, ScanReport report)
    {
        var sb = new StringBuilder();
        var s = report.Summary;

        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>ZeroBreach Scan Report — ")
          .Append(H(report.Host)).Append("</title><style>")
          .Append("body{font-family:Segoe UI,Arial,sans-serif;margin:2em;background:#f7f8fa;color:#1c2330}")
          .Append("h1{font-size:1.5em}h2{font-size:1.15em;margin-top:1.8em}")
          .Append("table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}")
          .Append("th,td{padding:.5em .7em;border-bottom:1px solid #e3e6ec;text-align:left;font-size:.9em;vertical-align:top}")
          .Append("th{background:#232a3a;color:#fff;position:sticky;top:0}")
          .Append("code{font-family:Consolas,monospace;font-size:.95em;word-break:break-all}")
          .Append(".sev{font-weight:700;padding:.15em .5em;border-radius:3px;color:#fff;font-size:.8em;white-space:nowrap}")
          .Append(".CRITICAL{background:#c0182b}.HIGH{background:#e06a00}.POSSIBLE{background:#c9a400}.INFO{background:#5b6472}")
          .Append(".badge{background:#2e7d32;color:#fff;border-radius:3px;padding:.1em .4em;font-size:.75em;margin-left:.4em}")
          .Append(".verdict{padding:1em;border-radius:6px;background:#fff;border-left:6px solid #888;margin:1em 0;font-weight:600}")
          .Append(".v-crit{border-color:#c0182b}.v-high{border-color:#e06a00}.v-poss{border-color:#c9a400}.v-warn{border-color:#5b6472}.v-ok{border-color:#2e7d32}")
          .Append(".muted{color:#5b6472;font-size:.85em}")
          .Append("</style></head><body>");

        sb.Append("<h1>ZeroBreach Scan Report</h1><p class=\"muted\">Host <b>").Append(H(report.Host))
          .Append("</b> &middot; mode ").Append(H(report.Mode))
          .Append(" &middot; started ").Append(report.StartedUtc.ToString("u"))
          .Append(" &middot; engine v").Append(H(report.Version))
          .Append(" &middot; elapsed ").Append(s.ElapsedSeconds.ToString("0")).Append("s");
        // Engagement metadata (spec §7) — only present when the report carries it.
        if (report.CaseId is not null) sb.Append(" &middot; case <b>").Append(H(report.CaseId)).Append("</b>");
        if (report.Operator is not null) sb.Append(" &middot; operator <b>").Append(H(report.Operator)).Append("</b>");
        sb.Append("</p>");

        var vClass = s.Critical > 0 ? "v-crit" : s.High > 0 ? "v-high" : s.Possible > 0 ? "v-poss"
            : (s.ChecksInconclusive > 0 || s.ChecksSkipped > 0) ? "v-warn" : "v-ok";
        sb.Append($"<div class=\"verdict {vClass}\">").Append(H(s.Verdict)).Append("</div>");

        sb.Append("<p><b>").Append(s.Critical).Append("</b> critical &middot; <b>").Append(s.High)
          .Append("</b> high &middot; <b>").Append(s.Possible).Append("</b> possible &middot; <b>")
          .Append(s.Info).Append("</b> info &middot; checks: ").Append(s.ChecksCompleted)
          .Append(" completed, ").Append(s.ChecksInconclusive).Append(" inconclusive, ")
          .Append(s.ChecksSkipped).Append(" skipped</p>");

        // Baseline suppression must be visible in the artifact of record (spec §6.7): a
        // diffed report showing a quiet machine without saying findings were suppressed
        // would read as a clean bill it isn't.
        if (report.Baseline is { } b)
        {
            sb.Append("<div class=\"verdict v-warn\">Baseline diff applied — <b>").Append(b.Suppressed)
              .Append("</b> known finding(s) suppressed (baseline from host <b>").Append(H(b.Host))
              .Append("</b>, created ").Append(b.CreatedUtc.ToString("u")).Append(").");
            foreach (var w in b.Warnings)
                sb.Append("<br>&#9888; ").Append(H(w));
            sb.Append("</div>");
        }

        if (report.Findings.Count > 0)
        {
            sb.Append("<h2>Findings</h2><table><tr><th>Severity</th><th>Group</th><th>Description</th><th>Target</th><th>Suggested fix</th><th>MITRE</th></tr>");
            foreach (var f in report.Findings)
            {
                sb.Append("<tr><td><span class=\"sev ").Append(H(f.Severity)).Append("\">").Append(H(f.Severity)).Append("</span>")
                  .Append(f.VendorTrusted ? "<span class=\"badge\">vendor-trusted</span>" : "")
                  .Append("</td><td>").Append(H(f.Group))
                  .Append("</td><td>").Append(H(f.Description))
                  .Append("</td><td><code>").Append(H(f.Target)).Append("</code>")
                  .Append("</td><td>").Append(H(f.FixAction))
                  .Append(f.FixParam is null ? "" : "<br><code>" + H(f.FixParam) + "</code>")
                  .Append("</td><td>").Append(f.Mitre is null ? "" : H($"{f.Mitre.TechniqueId} {f.Mitre.TechniqueName}"))
                  .Append("</td></tr>");
            }
            sb.Append("</table>");
        }

        var notClean = report.Checks.Where(c => c.Outcome != "completed").ToList();
        if (notClean.Count > 0)
        {
            sb.Append("<h2>Checks that did not complete</h2>")
              .Append("<p class=\"muted\">These areas were <b>not cleared</b> — absence of findings above says nothing about them.</p>")
              .Append("<table><tr><th>Phase</th><th>Check</th><th>Outcome</th><th>Detail</th></tr>");
            foreach (var c in notClean)
                sb.Append("<tr><td>").Append(c.Phase).Append("</td><td>").Append(H(c.Check))
                  .Append("</td><td>").Append(H(c.Outcome)).Append("</td><td>").Append(H(c.Detail ?? ""))
                  .Append("</td></tr>");
            sb.Append("</table>");
        }

        // Per-phase wall-clock timings (spec §7) — only present when the report carries them.
        if (report.Phases is { Count: > 0 })
        {
            sb.Append("<h2>Phase timings</h2><table><tr><th>Phase</th><th>Name</th><th>Elapsed</th><th>Findings</th></tr>");
            foreach (var p in report.Phases)
                sb.Append("<tr><td>").Append(p.Phase).Append("</td><td>").Append(H(p.Name))
                  .Append("</td><td>").Append(p.ElapsedSeconds.ToString("0.###")).Append("s</td><td>")
                  .Append(p.Findings).Append("</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("</body></html>");
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static string H(string text) => WebUtility.HtmlEncode(text);
}
