// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Microsoft.Win32;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 10 — Event Log correlation (EVTX-001..EVTX-008 plus the cross-phase correlation
/// pass). All access goes through System.Diagnostics.Eventing.Reader with XPath filters
/// bounded by event-ID list, a time window, and an enumeration budget — never an unfiltered
/// read of a large log. Every channel gets a lightweight precondition probe; a disabled or
/// unreadable channel makes the dependent check Inconclusive naming that channel (spec
/// §6.7 — a check that could not look is never "clean"). "Log readable but no matches" is
/// Completed; "log unreadable/disabled/missing" is Inconclusive.
/// Default lookback when no --since filter is given: 14 days at FULL, 30 days at DEEP;
/// every check states the window it used in its detail string.
/// </summary>
public sealed class EventLogScanner : IScanner
{
    public int Phase => 10;
    public string Name => "Event Log Correlation";
    public string Group => "EventLog";
    public ScanDepth MinDepth => ScanDepth.Full;

    private const string SecurityLog = "Security";
    private const string SystemLog = "System";
    private const string PsOperationalLog = "Microsoft-Windows-PowerShell/Operational";
    private const string PsClassicLog = "Windows PowerShell";
    private const string DefenderLog = "Microsoft-Windows-Windows Defender/Operational";
    private const string WmiActivityLog = "Microsoft-Windows-WMI-Activity/Operational";
    private const string RdpConnMgrLog = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        var win = Window(ctx);
        CheckLogClearing(ctx, sink, win);          // EVTX-001
        CheckServiceInstalls(ctx, sink, win);      // EVTX-002
        CheckProcessCreation(ctx, sink, win);      // EVTX-003
        CheckAccountManipulation(ctx, sink, win);  // EVTX-004
        CheckRemoteAccess(ctx, sink, win);         // EVTX-005
        CheckPowerShellActivity(ctx, sink, win);   // EVTX-006
        CheckDefenderHistory(ctx, sink, win);      // EVTX-007
        CheckWmiActivity(ctx, sink, win);          // EVTX-008 (DEEP)
        CorrelationPass(ctx, sink);                // EVTX-CORR
    }

    // ---------------------------------------------------------------- EVTX-001

    private void CheckLogClearing(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-001 log clearing";
        try
        {
            var gaps = new List<string>();
            var hits = 0;

            foreach (var (channel, id, provider) in new[]
            {
                (SecurityLog, 1102, "Microsoft-Windows-Security-Auditing"),
                (SystemLog, 104, "Microsoft-Windows-Eventlog"),
            })
            {
                if (ProbeChannel(channel) is string reason) { gaps.Add(reason); continue; }
                var budget = ctx.CreateBudget(500, TimeSpan.FromSeconds(10));
                var res = QueryEvents(ctx, channel, XPathFor(new[] { id }, win.SinceUtc), budget);
                if (res.Error is not null) { gaps.Add(res.Error); continue; }
                if (res.Truncated) gaps.Add($"{channel}: {budget.ExhaustedReason}");

                foreach (var e in res.Events)
                {
                    if (e.Provider is not null &&
                        !e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase)) continue;

                    var cleared = id == 1102 ? SecurityLog : Get(e, "Channel", SystemLog);
                    var who = JoinUser(Get(e, "SubjectDomainName"), Get(e, "SubjectUserName"));
                    var when = e.TimeUtc?.ToString("u") ?? "unknown time";
                    // HIGH always; CRITICAL when it falls inside an operator-set --since window.
                    var sev = ctx.SinceUtc is not null && ctx.WithinTimeWindow(e.TimeUtc)
                        ? Severity.Critical : Severity.High;
                    hits++;
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, cleared, $"EVTX-001:{id}:{when}"),
                        Severity = sev,
                        Description = $"Event log '{cleared}' was CLEARED at {when} by {who} " +
                                      $"({channel} event {id}). Log clearing is a hallmark of " +
                                      "anti-forensics; treat all earlier telemetry on this host " +
                                      $"as suspect. {win.Label}.",
                        Target = cleared,
                        Group = Group,
                        Check = "EVTX-001",
                        Mitre = new MitreRef("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
                    });
                }
            }

            Conclude(sink, check, gaps, $"Security 1102 + System 104, {win.Label}, {hits} clear event(s)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-002

    private void CheckServiceInstalls(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-002 service installation";
        try
        {
            var gaps = new List<string>();
            var pathSuspects = ctx.Signatures.Set("eventlog.service_imagepath_suspect");
            var benignTransient = ctx.Signatures.Set("eventlog.service_install_benign_transient");
            int svc7045 = 0, svc4697 = 0;

            if (ProbeChannel(SystemLog) is string sysReason) gaps.Add(sysReason);
            else
            {
                var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(20));
                var res = QueryEvents(ctx, SystemLog, XPathFor(new[] { 7045 }, win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add(res.Error);
                else
                {
                    if (res.Truncated) gaps.Add($"{SystemLog} 7045: {budget.ExhaustedReason}");
                    foreach (var e in res.Events)
                    {
                        svc7045++;
                        ReportServiceInstall(ctx, sink, win, e,
                            Get(e, "ServiceName"), Get(e, "ImagePath"), 7045, pathSuspects, benignTransient);
                    }
                }
            }

            // Security 4697 exists only where "Audit Security System Extension" is on;
            // zero events there is normal, but an unreadable Security log is a coverage gap.
            if (ProbeChannel(SecurityLog) is string secReason) gaps.Add($"4697 side: {secReason}");
            else
            {
                var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(20));
                var res = QueryEvents(ctx, SecurityLog, XPathFor(new[] { 4697 }, win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add($"4697 side: {res.Error}");
                else
                {
                    if (res.Truncated) gaps.Add($"{SecurityLog} 4697: {budget.ExhaustedReason}");
                    foreach (var e in res.Events)
                    {
                        svc4697++;
                        ReportServiceInstall(ctx, sink, win, e,
                            Get(e, "ServiceName"), Get(e, "ServiceFileName"), 4697, pathSuspects, benignTransient);
                    }
                }
            }

            var extra = svc4697 == 0 ? " (no 4697s — subcategory may not be audited)" : "";
            Conclude(sink, check, gaps,
                $"System 7045: {svc7045}, Security 4697: {svc4697}{extra}, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    private void ReportServiceInstall(ScanContext ctx, IFindingSink sink, Lookback win, Evt e,
        string name, string image, int eventId, IReadOnlyList<IndicatorEntry> pathSuspects,
        IReadOnlyList<IndicatorEntry> benignTransient)
    {
        if (name.Length == 0 && image.Length == 0) return;

        var stillExists = ServiceExists(name, image);
        var match = pathSuspects.FirstOrDefault(i => i.Matches(image));
        // Platform services that install and remove themselves by design (Defender's
        // definition drivers above all) show the exact install-run-remove shape below.
        var benign = benignTransient.FirstOrDefault(i => i.Matches(name) || i.Matches(image));
        var sev = Severity.Possible;
        var why = new List<string>();

        if (!stillExists)
        {
            if (benign is null)
            {
                sev = Severity.High;
                why.Add("service no longer exists — install-run-remove is a classic attacker pattern");
            }
            else
            {
                why.Add("service no longer exists, which is normal for this component");
            }
        }
        if (match is not null)
        {
            var msev = CapSeverity(match);
            if (msev > sev) sev = msev;
            why.Add(match.Note ?? $"image path matches suspicious pattern '{match.Pattern}'");
        }
        var ioc = MatchCustomText(ctx, image);
        if (ioc is not null)
            why.Add($"image path matches custom IOC '{ioc}'");

        if (benign is not null)
        {
            // Still reported — a machine-managed service is not automatically trustworthy, and
            // §6.7 forbids hiding what was observed — but it can never carry the transient- or
            // path-derived severity, which fired on every clean box. An operator's own IOC hit
            // still outranks the allowance.
            sev = ioc is null ? Severity.Info : Severity.Possible;
            why.Add(benign.Note ?? "known self-removing platform service");
        }

        // 7045 carries the run-as account ("AccountName"); 4697 carries the installer identity.
        var who = Get(e, "SubjectUserName").Length > 0
            ? $"by {JoinUser(Get(e, "SubjectDomainName"), Get(e, "SubjectUserName"))}"
            : $"runs as {Get(e, "AccountName", "unknown account")}";
        var when = e.TimeUtc?.ToString("u") ?? "unknown time";

        sink.Report(new Finding
        {
            Id = Finding.ComputeId(Group, name.Length > 0 ? name : image, $"EVTX-002:{eventId}:{image}"),
            Severity = sev,
            Description = $"Service '{name}' installed {when} (event {eventId}, {who}), " +
                          $"ImagePath: {Trunc(Flat(image), 200)}. " +
                          (why.Count > 0 ? string.Join("; ", why) + ". " : "New service inside the scan window. ") +
                          $"Cross-reference the persistence phase (PERS-004) for live service state. {win.Label}.",
            Target = image.Length > 0 ? image : name,
            Group = Group,
            Check = "EVTX-002",
            VendorTrusted = ctx.Signatures.IsVendorTrusted(image),
            Mitre = new MitreRef("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
        });
    }

    // ---------------------------------------------------------------- EVTX-003

    private void CheckProcessCreation(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-003 process creation heuristics";
        try
        {
            if (ProbeChannel(SecurityLog) is string reason)
            {
                sink.Inconclusive(Phase, check, reason);
                return;
            }

            var budget = ctx.CreateBudget(15000, TimeSpan.FromSeconds(45));
            var res = QueryEvents(ctx, SecurityLog, XPathFor(new[] { 4688 }, win.SinceUtc), budget);
            if (res.Error is not null) { sink.Inconclusive(Phase, check, res.Error); return; }
            if (res.Events.Count == 0)
            {
                sink.Inconclusive(Phase, check,
                    $"no 4688 events found ({win.Label}) — process-creation auditing appears " +
                    "disabled (enable 'Audit Process Creation'); check could not run");
                return;
            }

            var parents = ctx.Signatures.Set("eventlog.office_browser_parents");
            var children = ctx.Signatures.Set("eventlog.spawn_suspect_children");
            var lolbins = ctx.Signatures.Set("eventlog.lolbin_commandlines");
            var recon = ctx.Signatures.Set("eventlog.recon_commands");
            var suspectNames = ctx.Signatures.Set("eventlog.suspect_process_names");

            var withCmdline = 0;
            var parentFieldPresent = false;
            var pairSeen = new Dictionary<string, (Evt e, string parent, string child, int count)>(StringComparer.OrdinalIgnoreCase);
            var lolbinSeen = new Dictionary<string, (Evt e, IndicatorEntry ind, string image, string cmd, int count)>(StringComparer.OrdinalIgnoreCase);
            var reconByParent = new Dictionary<string, Dictionary<string, (string example, Severity sev)>>(StringComparer.OrdinalIgnoreCase);
            var nameSeen = new Dictionary<string, (Evt e, IndicatorEntry ind, string image)>(StringComparer.OrdinalIgnoreCase);
            var iocSeen = new Dictionary<string, (Evt e, string image, string ioc)>(StringComparer.OrdinalIgnoreCase);

            foreach (var e in res.Events)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var image = Get(e, "NewProcessName");
                var cmd = Get(e, "CommandLine");
                var parent = Get(e, "ParentProcessName");
                if (cmd.Length > 0) withCmdline++;
                if (parent.Length > 0) parentFieldPresent = true;

                // Office/browser parent spawning a script host or shell (works name-only).
                if (parent.Length > 0 && parents.Any(p => p.Matches(parent)) &&
                    children.Any(c => c.Matches(image)))
                {
                    var key = $"{FileName(parent)}>{image}";
                    pairSeen[key] = pairSeen.TryGetValue(key, out var pv)
                        ? (pv.e, pv.parent, pv.child, pv.count + 1)
                        : (e, parent, image, 1);
                }

                var hay = cmd.Length > 0 ? cmd : FileName(image);

                // LOLBin command-line patterns need a real command line.
                if (cmd.Length > 0 && lolbins.FirstOrDefault(i => i.Matches(cmd)) is IndicatorEntry lb)
                {
                    var key = $"{lb.Pattern}|{image}";
                    lolbinSeen[key] = lolbinSeen.TryGetValue(key, out var lv)
                        ? (lv.e, lv.ind, lv.image, lv.cmd, lv.count + 1)
                        : (e, lb, image, cmd, 1);
                }

                // Recon tally per parent (bursts of distinct recon shapes from one parent).
                foreach (var ri in recon)
                {
                    if (!ri.Matches(hay)) continue;
                    var pkey = parent.Length > 0 ? FileName(parent) : "(unknown parent)";
                    if (!reconByParent.TryGetValue(pkey, out var perParent))
                        reconByParent[pkey] = perParent = new Dictionary<string, (string, Severity)>(StringComparer.Ordinal);
                    if (!perParent.ContainsKey(ri.Pattern))
                        perParent[ri.Pattern] = (hay, CapSeverity(ri));
                }

                // Known-tool image names (works in degraded name-only mode too).
                if (suspectNames.FirstOrDefault(i => i.Matches(FileName(image))) is IndicatorEntry nm)
                    nameSeen[$"{nm.Pattern}|{image}"] = (e, nm, image);

                if (MatchCustomText(ctx, hay) is string ioc)
                    iocSeen[$"{ioc}|{image}"] = (e, image, ioc);
            }

            foreach (var kv in pairSeen)
            {
                var v = kv.Value;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, v.child, $"EVTX-003:parentchild:{FileName(v.parent)}"),
                    Severity = Severity.High,
                    Description = $"Office/browser process '{v.parent}' spawned '{v.child}' " +
                                  $"({v.count}x in window, seen {v.e.TimeUtc:u}) — document/drive-by " +
                                  $"payload execution pattern. {win.Label}.",
                    Target = v.child,
                    Group = Group,
                    Check = "EVTX-003",
                    VendorTrusted = ctx.Signatures.IsVendorTrusted(v.child),
                    Mitre = new MitreRef("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
                });
            }

            foreach (var kv in lolbinSeen)
            {
                var v = kv.Value;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, v.image, $"EVTX-003:lolbin:{v.ind.Pattern}"),
                    Severity = CapSeverity(v.ind),
                    Description = "Process creation (4688) command line matched LOLBin pattern" +
                                  (v.ind.Note is null ? "" : $" ({v.ind.Note})") +
                                  $": {Trunc(Flat(v.cmd), 260)} ({v.count}x, seen {v.e.TimeUtc:u}). {win.Label}.",
                    Target = v.image,
                    Group = Group,
                    Check = "EVTX-003",
                    VendorTrusted = ctx.Signatures.IsVendorTrusted(v.image),
                    Mitre = v.ind.Mitre,
                });
            }

            foreach (var kv in reconByParent)
            {
                var pats = kv.Value;
                var maxInd = pats.Values.Max(p => p.sev);
                var n = pats.Count;
                if (n == 1 && maxInd < Severity.High) continue; // single common recon command: noise
                var baseSev = n >= 3 ? Severity.High : Severity.Possible;
                var sev = (Severity)Math.Max((int)baseSev, (int)maxInd);
                var sorted = pats.Keys.OrderBy(p => p, StringComparer.Ordinal).ToList();
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, kv.Key, $"EVTX-003:recon:{string.Join(",", sorted)}"),
                    Severity = sev,
                    Description = $"Reconnaissance activity from parent '{kv.Key}': {n} distinct recon " +
                                  "command shape(s) in window — " +
                                  string.Join(" | ", pats.Values.Take(5).Select(p => Trunc(Flat(p.example), 80))) +
                                  $". {win.Label}.",
                    Target = kv.Key,
                    Group = Group,
                    Check = "EVTX-003",
                    Mitre = new MitreRef("T1087", "Account Discovery", "Discovery"),
                });
            }

            foreach (var kv in nameSeen)
            {
                var v = kv.Value;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, v.image, $"EVTX-003:name:{v.ind.Pattern}"),
                    Severity = CapSeverity(v.ind),
                    Description = $"Process creation (4688): image name matches known-tool pattern '{v.ind.Pattern}'" +
                                  (v.ind.Note is null ? "" : $" ({v.ind.Note})") +
                                  $" — {v.image} at {v.e.TimeUtc:u}. Name-only evidence; corroborate " +
                                  $"with file inspection. {win.Label}.",
                    Target = v.image,
                    Group = Group,
                    Check = "EVTX-003",
                    VendorTrusted = ctx.Signatures.IsVendorTrusted(v.image),
                    Mitre = v.ind.Mitre,
                });
            }

            foreach (var kv in iocSeen)
            {
                var v = kv.Value;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, v.image, $"EVTX-003:ioc:{v.ioc}"),
                    Severity = Severity.Possible,
                    Description = $"Process creation (4688) matched operator-supplied IOC '{v.ioc}' " +
                                  $"({v.image}, seen {v.e.TimeUtc:u}). Custom-IOC hits require operator " +
                                  $"judgment. {win.Label}.",
                    Target = v.image,
                    Group = Group,
                    Check = "EVTX-003",
                });
            }

            var gaps = new List<string>();
            if (res.Truncated) gaps.Add(budget.ExhaustedReason ?? "budget exhausted");
            if (withCmdline == 0)
                gaps.Add("command-line auditing not enabled — degraded to process-name-only matching " +
                         "(partial results); enable 'Include command line in process creation events'");
            else if (!parentFieldPresent)
                gaps.Add("ParentProcessName absent from 4688 (older OS) — parent/child heuristic could not run");

            Conclude(sink, check, gaps, $"{res.Events.Count} 4688 event(s) examined, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-004

    private void CheckAccountManipulation(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-004 account manipulation";
        try
        {
            if (ProbeChannel(SecurityLog) is string reason)
            {
                sink.Inconclusive(Phase, check, reason);
                return;
            }

            var gaps = new List<string>();
            var privileged = ctx.Signatures.Set("eventlog.privileged_groups");

            var budget1 = ctx.CreateBudget(6000, TimeSpan.FromSeconds(30));
            var res = QueryEvents(ctx, SecurityLog,
                XPathFor(new[] { 4720, 4724, 4728, 4732, 4738 }, win.SinceUtc), budget1);
            if (res.Error is not null) { sink.Inconclusive(Phase, check, res.Error); return; }
            if (res.Truncated) gaps.Add($"account events: {budget1.ExhaustedReason}");

            var creations = new List<(Evt e, string user, string sid, string who)>();
            var groupAdds = new List<(Evt e, string grp, string member, string sid, string who, bool priv)>();
            var resets = new List<(Evt e, string user, string who)>();
            var changed = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var e in res.Events)
            {
                var who = JoinUser(Get(e, "SubjectDomainName"), Get(e, "SubjectUserName"));
                switch (e.Id)
                {
                    case 4720:
                        creations.Add((e, Get(e, "TargetUserName"), Get(e, "TargetSid"), who));
                        break;
                    case 4724:
                        resets.Add((e, Get(e, "TargetUserName"), who));
                        break;
                    case 4728:
                    case 4732:
                        var grp = Get(e, "TargetUserName");
                        // Windows writes a literal "-" in MemberName when the member is only
                        // identified by SID; treating that as a name produced the unactionable
                        // "Member '-'" finding. The SID is the real identity — keep both.
                        var memberName = Clean(Get(e, "MemberName"));
                        var memberSid = Clean(Get(e, "MemberSid"));
                        groupAdds.Add((e, grp, memberName, memberSid, who,
                            privileged.Any(p => p.Matches(grp))));
                        break;
                    case 4738:
                        var t = Get(e, "TargetUserName");
                        changed[t] = changed.TryGetValue(t, out var n) ? n + 1 : 1;
                        break;
                }
            }

            foreach (var c in creations)
            {
                if (c.user.Length == 0) continue;
                var laterPriv = groupAdds.Any(g => g.priv &&
                    (g.member.Contains(c.user, StringComparison.OrdinalIgnoreCase) ||
                     (c.sid.Length > 0 && string.Equals(g.sid, c.sid, StringComparison.OrdinalIgnoreCase))));
                var mods = changed.TryGetValue(c.user, out var m) ? m : 0;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, c.user, $"EVTX-004:4720:{c.sid}"),
                    Severity = laterPriv ? Severity.High : Severity.Possible,
                    Description = $"Account '{c.user}' created at {c.e.TimeUtc:u} by {c.who} (4720)" +
                                  (laterPriv ? " and subsequently ADDED TO A PRIVILEGED GROUP in the same window" : "") +
                                  (mods > 0 ? $"; account modified {mods}x (4738) in window" : "") +
                                  $". {win.Label}.",
                    Target = c.user,
                    Group = Group,
                    Check = "EVTX-004",
                    Mitre = new MitreRef("T1136.001", "Create Account: Local Account", "Persistence"),
                });
            }

            foreach (var g in groupAdds)
            {
                if (g.grp.Length == 0) continue;
                if (g.member.Length == 0 && g.sid.Length == 0) continue; // nothing identifiable

                // A machine-managed principal (virtual service account, IIS app pool, machine
                // account) added to a local group is what service installers do; it is not the
                // hands-on-keyboard privilege escalation 4732 is watched for. Report it, but
                // never as HIGH — that fired on every clean box with a service installed.
                var machinePrincipal = IsMachinePrincipal(g.sid, g.member);
                var identity = Identify(g.member, g.sid);
                var sev = g.priv && !machinePrincipal ? Severity.High : Severity.Possible;

                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, g.grp,
                        $"EVTX-004:{g.e.Id}:{(g.sid.Length > 0 ? g.sid : g.member)}"),
                    Severity = sev,
                    Description = $"Member {identity} added to group '{g.grp}' at {g.e.TimeUtc:u} " +
                                  $"by {g.who} (event {g.e.Id})" +
                                  (g.priv && !machinePrincipal
                                      ? " — PRIVILEGED group addition inside the scan window"
                                      : "") +
                                  (machinePrincipal
                                      ? " — the member is a machine-managed principal (virtual service " +
                                        "account / machine account), which service installers add " +
                                        "routinely; confirm the installing product was expected"
                                      : "") +
                                  $". {win.Label}.",
                    Target = g.grp,
                    Group = Group,
                    Check = "EVTX-004",
                    Mitre = new MitreRef("T1098", "Account Manipulation", "Privilege Escalation"),
                });
            }

            foreach (var r in resets)
            {
                if (r.user.Length == 0) continue;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, r.user, "EVTX-004:4724"),
                    Severity = Severity.Possible,
                    Description = $"Password reset attempted for '{r.user}' by {r.who} at " +
                                  $"{r.e.TimeUtc:u} (4724) — verify this was an authorized helpdesk " +
                                  $"action. {win.Label}.",
                    Target = r.user,
                    Group = Group,
                    Check = "EVTX-004",
                    Mitre = new MitreRef("T1098", "Account Manipulation", "Persistence"),
                });
            }

            // 4625 failure bursts followed by a 4624 success (spray -> hit).
            var failTotal = 0;
            var budget2 = ctx.CreateBudget(15000, TimeSpan.FromSeconds(30));
            var fres = QueryEvents(ctx, SecurityLog, XPathFor(new[] { 4625 }, win.SinceUtc), budget2);
            if (fres.Error is not null) gaps.Add($"4625: {fres.Error}");
            else
            {
                if (fres.Truncated) gaps.Add($"4625: {budget2.ExhaustedReason}");
                failTotal = fres.Events.Count;

                var byAccount = new Dictionary<string, (int count, DateTime? firstUtc, SortedSet<string> sources)>(StringComparer.OrdinalIgnoreCase);
                foreach (var e in fres.Events)
                {
                    var u = Get(e, "TargetUserName");
                    if (u.Length == 0 || u.EndsWith("$", StringComparison.Ordinal)) continue;
                    if (!byAccount.TryGetValue(u, out var v))
                        v = (0, e.TimeUtc, new SortedSet<string>(StringComparer.OrdinalIgnoreCase));
                    v.count++;
                    if (e.TimeUtc is not null && (v.firstUtc is null || e.TimeUtc < v.firstUtc)) v.firstUtc = e.TimeUtc;
                    var ip = Get(e, "IpAddress");
                    if (ip.Length > 0 && ip != "-") v.sources.Add(ip);
                    byAccount[u] = v;
                }

                var probes = 0;
                var capped = false;
                foreach (var kv in byAccount.Where(k => k.Value.count >= 5)
                                            .OrderByDescending(k => k.Value.count))
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    var acct = kv.Key;
                    Evt? success = null;

                    if (probes >= 10) { capped = true; }
                    else if (!acct.Contains('\''))
                    {
                        probes++;
                        var sb = ctx.CreateBudget(50, TimeSpan.FromSeconds(5));
                        var sres = QueryEvents(ctx, SecurityLog,
                            XPathSuccessForAccount(acct, win.SinceUtc), sb);
                        if (sres.Error is null)
                            success = sres.Events.FirstOrDefault(s =>
                                s.TimeUtc is not null && kv.Value.firstUtc is not null &&
                                s.TimeUtc > kv.Value.firstUtc);
                    }

                    var srcs = kv.Value.sources.Count > 0
                        ? string.Join(", ", kv.Value.sources.Take(5)) : "unknown sources";
                    if (success is not null)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, acct, "EVTX-004:sprayhit"),
                            Severity = Severity.High,
                            Description = $"{kv.Value.count} failed logons (4625) for '{acct}' " +
                                          $"(sources: {srcs}) FOLLOWED BY a successful logon (4624, " +
                                          $"type {Get(success, "LogonType")}, source {Get(success, "IpAddress", "unknown")}) " +
                                          $"at {success.TimeUtc:u} — brute-force/spray-then-success " +
                                          $"pattern. {win.Label}.",
                            Target = acct,
                            Group = Group,
                            Check = "EVTX-004",
                            Mitre = new MitreRef("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
                        });
                    }
                    else if (kv.Value.count >= 10)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, acct, "EVTX-004:failburst"),
                            Severity = Severity.Possible,
                            Description = $"{kv.Value.count} failed logons (4625) for '{acct}' " +
                                          $"(sources: {srcs}) with no matching success found — " +
                                          $"possible brute-force attempt. {win.Label}.",
                            Target = acct,
                            Group = Group,
                            Check = "EVTX-004",
                            Mitre = new MitreRef("T1110", "Brute Force", "Credential Access"),
                        });
                    }
                }
                if (capped) gaps.Add("spray success-probe capped at 10 accounts (highest failure counts checked first)");
            }

            Conclude(sink, check, gaps,
                $"account events: {res.Events.Count}, 4625 failures: {failTotal}, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-005

    private void CheckRemoteAccess(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-005 remote access logons";
        try
        {
            var gaps = new List<string>();
            var flagged = 0;
            var examined = 0;

            if (ProbeChannel(SecurityLog) is string r1) gaps.Add(r1);
            else
            {
                var budget = ctx.CreateBudget(20000, TimeSpan.FromSeconds(45));
                var res = QueryEvents(ctx, SecurityLog, XPathLogonTypes(win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add(res.Error);
                else
                {
                    if (res.Truncated) gaps.Add($"4624: {budget.ExhaustedReason}");
                    examined = res.Events.Count;

                    var agg = new Dictionary<string, (Evt e, int count, string type, string user, string ip, bool pub)>(StringComparer.OrdinalIgnoreCase);
                    foreach (var e in res.Events)
                    {
                        var type = Get(e, "LogonType");
                        if (type != "10" && type != "3") continue;
                        var user = Get(e, "TargetUserName");
                        if (user.Length == 0 || user.EndsWith("$", StringComparison.Ordinal)) continue;
                        var ip = Get(e, "IpAddress");
                        var pub = !IsPrivateOrLocal(ip);
                        var iocHit = ip.Length > 0 && MatchCustomText(ctx, ip) is not null;
                        // Type-3 (network) logons from private space are ubiquitous — only
                        // non-RFC1918 / custom-IOC sources are signal. Type-10 (RDP) always is.
                        if (type == "3" && !pub && !iocHit) continue;

                        var key = $"{type}|{user}|{ip}";
                        agg[key] = agg.TryGetValue(key, out var v)
                            ? (v.e, v.count + 1, v.type, v.user, v.ip, v.pub)
                            : (e, 1, type, user, ip, pub);
                    }

                    foreach (var kv in agg)
                    {
                        var v = kv.Value;
                        var rdp = v.type == "10";
                        flagged++;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, v.user, $"EVTX-005:{v.type}:{v.ip}"),
                            Severity = v.pub ? Severity.High : Severity.Possible,
                            Description = $"{v.count} {(rdp ? "RDP (logon type 10)" : "network (logon type 3)")} " +
                                          $"logon(s) for '{v.user}' from " +
                                          $"{(v.ip.Length > 0 && v.ip != "-" ? v.ip : "unknown source")}" +
                                          (v.pub ? " — source is OUTSIDE private address space" : "") +
                                          $". Most recent {v.e.TimeUtc:u}. {win.Label}.",
                            Target = v.user,
                            Group = Group,
                            Check = "EVTX-005",
                            Mitre = rdp
                                ? new MitreRef("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement")
                                : new MitreRef("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
                        });
                    }
                }
            }

            // RDP connection-manager 1149 (pre-auth connection accepted).
            if (ProbeChannel(RdpConnMgrLog) is string r2) gaps.Add(r2);
            else
            {
                var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(15));
                var res = QueryEvents(ctx, RdpConnMgrLog, XPathFor(new[] { 1149 }, win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add(res.Error);
                else
                {
                    if (res.Truncated) gaps.Add($"1149: {budget.ExhaustedReason}");
                    var agg = new Dictionary<string, (Evt e, int count, string user, string ip, bool pub)>(StringComparer.OrdinalIgnoreCase);
                    foreach (var e in res.Events)
                    {
                        var user = JoinUser(Get(e, "Param2"), Get(e, "Param1"));
                        var ip = Get(e, "Param3");
                        var key = $"{user}|{ip}";
                        agg[key] = agg.TryGetValue(key, out var v)
                            ? (v.e, v.count + 1, v.user, v.ip, v.pub)
                            : (e, 1, user, ip, !IsPrivateOrLocal(ip));
                    }
                    foreach (var kv in agg)
                    {
                        var v = kv.Value;
                        flagged++;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, v.user, $"EVTX-005:1149:{v.ip}"),
                            Severity = v.pub ? Severity.High : Severity.Possible,
                            Description = $"{v.count} RDP connection(s) accepted for '{v.user}' from " +
                                          $"{(v.ip.Length > 0 ? v.ip : "unknown source")} " +
                                          $"(TerminalServices-RemoteConnectionManager 1149)" +
                                          (v.pub ? " — source is OUTSIDE private address space" : "") +
                                          $". Most recent {v.e.TimeUtc:u}. {win.Label}.",
                            Target = v.user,
                            Group = Group,
                            Check = "EVTX-005",
                            Mitre = new MitreRef("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
                        });
                    }
                }
            }

            Conclude(sink, check, gaps,
                $"{examined} type-3/10 logon event(s) examined, {flagged} source/account pair(s) flagged, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-006

    private void CheckPowerShellActivity(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-006 PowerShell activity";
        try
        {
            var gaps = new List<string>();
            var patterns = ctx.Signatures.Set("eventlog.ps_script_patterns");
            var sbPolicyOn = ScriptBlockPolicyEnabled();
            var ev4104 = 0;

            if (ProbeChannel(PsOperationalLog) is string r1) gaps.Add(r1);
            else
            {
                // 4104 script-block logs.
                var budget = ctx.CreateBudget(10000, TimeSpan.FromSeconds(45));
                var res = QueryEvents(ctx, PsOperationalLog, XPathFor(new[] { 4104 }, win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add(res.Error);
                else
                {
                    if (res.Truncated) gaps.Add($"4104: {budget.ExhaustedReason}");
                    ev4104 = res.Events.Count;

                    var agg4104 = new Dictionary<string, PatternAgg>(StringComparer.Ordinal);
                    var iocAgg = new Dictionary<string, (int count, string target, DateTime? last)>(StringComparer.OrdinalIgnoreCase);

                    foreach (var e in res.Events)
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        var text = Get(e, "ScriptBlockText");
                        if (text.Length == 0) continue;
                        var path = Get(e, "Path");
                        var tkey = path.Length > 0 ? path
                            : Get(e, "ScriptBlockId") is { Length: > 0 } sbid ? $"scriptblock {sbid}" : "(no path)";

                        foreach (var ind in patterns)
                        {
                            if (!ind.Matches(text)) continue;
                            if (!agg4104.TryGetValue(ind.Pattern, out var a))
                                agg4104[ind.Pattern] = a = new PatternAgg
                                {
                                    Ind = ind,
                                    Example = Trunc(Flat(text), 220),
                                    LastUtc = e.TimeUtc,
                                };
                            a.Count++;
                            a.Targets.Add(tkey);
                        }

                        if (MatchCustomText(ctx, text) is string ioc)
                        {
                            iocAgg[ioc] = iocAgg.TryGetValue(ioc, out var iv)
                                ? (iv.count + 1, iv.target, iv.last)
                                : (1, tkey, e.TimeUtc);
                        }
                    }

                    EmitPsPatternFindings(ctx, sink, win, agg4104, "4104 script-block log", "EVTX-006:4104");

                    foreach (var kv in iocAgg)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, kv.Value.target, $"EVTX-006:ioc:{kv.Key}"),
                            Severity = Severity.Possible,
                            Description = $"PowerShell script-block log (4104) matched operator-supplied " +
                                          $"IOC '{kv.Key}': {kv.Value.count} occurrence(s), source " +
                                          $"{kv.Value.target}, last {kv.Value.last:u}. {win.Label}.",
                            Target = kv.Value.target,
                            Group = Group,
                            Check = "EVTX-006",
                        });
                    }

                    // 4103 module logs (present only where module logging is on).
                    var budget3 = ctx.CreateBudget(4000, TimeSpan.FromSeconds(15));
                    var mres = QueryEvents(ctx, PsOperationalLog, XPathFor(new[] { 4103 }, win.SinceUtc), budget3);
                    if (mres.Error is not null) gaps.Add($"4103: {mres.Error}");
                    else
                    {
                        if (mres.Truncated) gaps.Add($"4103: {budget3.ExhaustedReason}");
                        var agg4103 = new Dictionary<string, PatternAgg>(StringComparer.Ordinal);
                        foreach (var e in mres.Events)
                        {
                            var payload = Get(e, "Payload");
                            if (payload.Length == 0) continue;
                            foreach (var ind in patterns)
                            {
                                if (!ind.Matches(payload)) continue;
                                if (!agg4103.TryGetValue(ind.Pattern, out var a))
                                    agg4103[ind.Pattern] = a = new PatternAgg
                                    {
                                        Ind = ind,
                                        Example = Trunc(Flat(payload), 220),
                                        LastUtc = e.TimeUtc,
                                    };
                                a.Count++;
                                a.Targets.Add(Get(e, "ContextInfo").Length > 0 ? "module pipeline" : "(module log)");
                            }
                        }
                        EmitPsPatternFindings(ctx, sink, win, agg4103, "4103 module log", "EVTX-006:4103");
                    }
                }
            }

            // Classic engine-lifecycle log: 400/403 with HostVersion/EngineVersion 2.0 = downgrade.
            if (ProbeChannel(PsClassicLog) is string r2) gaps.Add(r2);
            else
            {
                var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(15));
                var res = QueryEvents(ctx, PsClassicLog, XPathFor(new[] { 400, 403 }, win.SinceUtc), budget);
                if (res.Error is not null) gaps.Add(res.Error);
                else
                {
                    if (res.Truncated) gaps.Add($"400/403: {budget.ExhaustedReason}");
                    var count = 0;
                    DateTime? first = null, last = null;
                    foreach (var e in res.Events)
                    {
                        var joined = string.Join("\n", e.Unnamed);
                        if (!joined.Contains("HostVersion=2.0", StringComparison.OrdinalIgnoreCase) &&
                            !joined.Contains("EngineVersion=2.0", StringComparison.OrdinalIgnoreCase)) continue;
                        count++;
                        if (e.TimeUtc is not null)
                        {
                            if (first is null || e.TimeUtc < first) first = e.TimeUtc;
                            if (last is null || e.TimeUtc > last) last = e.TimeUtc;
                        }
                    }
                    if (count > 0)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, "powershell.exe (engine v2)", "EVTX-006:downgrade"),
                            Severity = Severity.High,
                            Description = $"PowerShell engine v2 start event(s) ({count}x, {first:u} .. {last:u}): " +
                                          "HostVersion/EngineVersion 2.0 in 'Windows PowerShell' 400/403. " +
                                          "v2 has no script-block logging or AMSI — a deliberate downgrade " +
                                          $"is a logging bypass. {win.Label}.",
                            Target = "powershell.exe (engine v2)",
                            Group = Group,
                            Check = "EVTX-006",
                            Mitre = new MitreRef("T1562.010", "Impair Defenses: Downgrade Attack", "Defense Evasion"),
                        });
                    }
                }
            }

            if (!sbPolicyOn && ev4104 == 0)
                gaps.Add("ScriptBlockLogging policy not enabled and no 4104 events found — " +
                         "script content over the window is invisible");

            Conclude(sink, check, gaps,
                $"4104: {ev4104} event(s), ScriptBlockLogging policy {(sbPolicyOn ? "on" : "off")}, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    private void EmitPsPatternFindings(ScanContext ctx, IFindingSink sink, Lookback win,
        Dictionary<string, PatternAgg> agg, string sourceLabel, string discPrefix)
    {
        foreach (var kv in agg)
        {
            var a = kv.Value;
            var target = a.Targets.Count > 0 ? a.Targets.Min! : "PowerShell script block";
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, target, $"{discPrefix}:{a.Ind.Pattern}"),
                Severity = CapSeverity(a.Ind),
                Description = $"PowerShell {sourceLabel} matched pattern '{a.Ind.Pattern}'" +
                              (a.Ind.Note is null ? "" : $" ({a.Ind.Note})") +
                              $": {a.Count} occurrence(s), sources: {string.Join("; ", a.Targets.Take(4))}. " +
                              $"Example: {a.Example}. Last seen {a.LastUtc:u}. {win.Label}.",
                Target = target,
                Group = Group,
                Check = "EVTX-006",
                VendorTrusted = ctx.Signatures.IsVendorTrusted(target),
                Mitre = a.Ind.Mitre ?? new MitreRef("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
            });
        }
    }

    // ---------------------------------------------------------------- EVTX-007

    private void CheckDefenderHistory(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-007 Defender history";
        try
        {
            if (ProbeChannel(DefenderLog) is string reason)
            {
                sink.Inconclusive(Phase, check,
                    $"{reason} — if a third-party AV is primary, review its own console/history manually");
                return;
            }

            var gaps = new List<string>();
            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(20));
            var res = QueryEvents(ctx, DefenderLog,
                XPathFor(new[] { 1116, 1117, 1118, 1119, 5001, 5010, 5012 }, win.SinceUtc), budget);
            if (res.Error is not null) { sink.Inconclusive(Phase, check, res.Error); return; }
            if (res.Truncated) gaps.Add(budget.ExhaustedReason ?? "budget exhausted");

            var detections = new Dictionary<string, (Evt e, string threat, string path, string proc)>(StringComparer.OrdinalIgnoreCase);
            var remediated = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var remFailed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var cfgAgg = new Dictionary<int, (int count, Evt e)>();

            foreach (var e in res.Events)
            {
                var threat = Get(e, "Threat Name");
                var path = Get(e, "Path");
                var key = $"{threat}|{path}";
                switch (e.Id)
                {
                    case 1116:
                        if (!detections.ContainsKey(key))
                            detections[key] = (e, threat, path, Get(e, "Process Name"));
                        break;
                    case 1117:
                        remediated.Add(key);
                        break;
                    case 1118:
                    case 1119:
                        remFailed.Add(key);
                        break;
                    case 5001:
                    case 5010:
                    case 5012:
                        cfgAgg[e.Id] = cfgAgg.TryGetValue(e.Id, out var v) ? (v.count + 1, v.e) : (1, e);
                        break;
                }
            }

            foreach (var kv in detections)
            {
                var d = kv.Value;
                var failed = remFailed.Contains(kv.Key);
                var ok = remediated.Contains(kv.Key);
                var state = failed
                    ? "remediation FAILED (1118/1119) — the threat may still be present"
                    : ok
                        ? "remediated (1117) — verify no residue or re-entry vector"
                        : "NO remediation recorded — the threat may still be present";
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, d.path.Length > 0 ? d.path : d.threat, $"EVTX-007:1116:{d.threat}"),
                    Severity = failed || !ok ? Severity.High : Severity.Possible,
                    Description = $"Defender detected '{d.threat}' at '{Trunc(Flat(d.path), 200)}'" +
                                  (d.proc.Length > 0 ? $" (process: {d.proc})" : "") +
                                  $" on {d.e.TimeUtc:u}; {state}. A prior detection is exactly the lead " +
                                  $"this scan exists to follow up. {win.Label}.",
                    Target = d.path.Length > 0 ? d.path : d.threat,
                    Group = Group,
                    Check = "EVTX-007",
                });
            }

            foreach (var kv in cfgAgg)
            {
                var label = kv.Key switch
                {
                    5001 => "real-time protection was DISABLED",
                    5010 => "anti-malware scanning was DISABLED",
                    _ => "anti-virus scanning was DISABLED",
                };
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, "Windows Defender", $"EVTX-007:{kv.Key}"),
                    Severity = Severity.High,
                    Description = $"Defender {label} ({kv.Value.count}x in window, event {kv.Key}, " +
                                  $"most recent {kv.Value.e.TimeUtc:u}). {win.Label}.",
                    Target = "Windows Defender",
                    Group = Group,
                    Check = "EVTX-007",
                    Mitre = new MitreRef("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
                });
            }

            Conclude(sink, check, gaps,
                $"{detections.Count} detection(s), {cfgAgg.Values.Sum(v => v.count)} protection-disable event(s), {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-008

    private void CheckWmiActivity(ScanContext ctx, IFindingSink sink, Lookback win)
    {
        const string check = "EVTX-008 WMI activity";
        try
        {
            if (ctx.Depth < ScanDepth.Deep)
            {
                sink.Skipped(Phase, check, "requires DEEP depth");
                return;
            }
            if (ProbeChannel(WmiActivityLog) is string reason)
            {
                sink.Inconclusive(Phase, check, reason);
                return;
            }

            var gaps = new List<string>();
            var budget = ctx.CreateBudget(6000, TimeSpan.FromSeconds(30));
            var res = QueryEvents(ctx, WmiActivityLog,
                XPathFor(new[] { 5857, 5860, 5861 }, win.SinceUtc), budget);
            if (res.Error is not null) { sink.Inconclusive(Phase, check, res.Error); return; }
            if (res.Truncated) gaps.Add(budget.ExhaustedReason ?? "budget exhausted");

            var providerSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var flagged = 0;

            foreach (var e in res.Events)
            {
                switch (e.Id)
                {
                    case 5861: // permanent event consumer registration
                    {
                        var ess = Get(e, "ESS");
                        var consumer = Get(e, "CONSUMER");
                        if (ess.Length == 0 && consumer.Length == 0)
                            consumer = Get(e, "PossibleCause", "(details unavailable)");
                        var target = Trunc(Flat(consumer.Length > 0 ? consumer : ess), 120);
                        flagged++;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, target, $"EVTX-008:5861:{Trunc(Flat(ess), 120)}"),
                            Severity = Severity.High,
                            Description = "PERMANENT WMI event consumer registered (5861) at " +
                                          $"{e.TimeUtc:u}. Filter: {Trunc(Flat(ess), 200)}; consumer: " +
                                          $"{Trunc(Flat(consumer), 200)}. Cross-reference the live WMI " +
                                          $"subscription check (PERS-005). {win.Label}.",
                            Target = target,
                            Group = Group,
                            Check = "EVTX-008",
                            Mitre = new MitreRef("T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence"),
                        });
                        break;
                    }
                    case 5860: // temporary event consumer
                    {
                        var ns = Get(e, "NamespaceName");
                        var query = Get(e, "Query");
                        if (query.Length == 0) continue;
                        var target = Trunc(Flat(query), 120);
                        flagged++;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, target, "EVTX-008:5860"),
                            Severity = Severity.Possible,
                            Description = $"Temporary WMI event consumer registered (5860) at {e.TimeUtc:u}, " +
                                          $"namespace {ns}, query: {Trunc(Flat(query), 200)}. {win.Label}.",
                            Target = target,
                            Group = Group,
                            Check = "EVTX-008",
                            Mitre = new MitreRef("T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence"),
                        });
                        break;
                    }
                    case 5857: // provider load — only interesting from a non-standard path
                    {
                        var provPath = Get(e, "ProviderPath");
                        if (provPath.Length == 0) continue;
                        if (provPath.Contains(@"\system32\wbem\", StringComparison.OrdinalIgnoreCase) ||
                            provPath.Contains(@"\syswow64\wbem\", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!providerSeen.Add(provPath)) continue;
                        flagged++;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, provPath, "EVTX-008:5857"),
                            Severity = Severity.Possible,
                            Description = $"WMI provider '{Get(e, "ProviderName", "(unknown)")}' loaded from " +
                                          $"non-standard path {provPath} (5857, {e.TimeUtc:u}). {win.Label}.",
                            Target = provPath,
                            Group = Group,
                            Check = "EVTX-008",
                            VendorTrusted = ctx.Signatures.IsVendorTrusted(provPath),
                            Mitre = new MitreRef("T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence"),
                        });
                        break;
                    }
                }
            }

            Conclude(sink, check, gaps,
                $"{res.Events.Count} WMI-activity event(s) examined, {flagged} flagged, {win.Label}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- EVTX-CORR

    /// <summary>End-of-phase-10 correlation pass (phase catalog): when ≥2 distinct check IDs
    /// from ≥2 distinct phases (approximated by finding group, which maps 1:1 to phase) hit
    /// the same normalized target, add a NEW correlation finding one severity step above the
    /// highest contributor (capped at CRITICAL). Original findings are never mutated —
    /// baseline diff depends on their stability. Deterministic: the discriminator is the
    /// sorted list of contributing check IDs.</summary>
    private void CorrelationPass(ScanContext ctx, IFindingSink sink)
    {
        const string check = "EVTX-CORR cross-phase correlation";
        try
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (sink is not FindingCollector collector)
            {
                sink.Skipped(Phase, check,
                    "sink does not expose collected findings — correlation pass unavailable in this host");
                return;
            }

            var emitted = 0;
            var derivedSuppressed = 0;
            var groups = collector.Findings
                .Where(f => !string.Equals(f.Group, "correlation", StringComparison.OrdinalIgnoreCase) &&
                            f.Check is not null &&
                            f.Target.Contains('\\') &&   // only path-like targets are specific enough
                            f.Target.Length >= 4)
                .Where(f =>
                {
                    // Circular-corroboration guard: a finding a later phase raised only because
                    // in-run escalation armed an indicator from an EARLIER finding is that
                    // finding's echo, not a second opinion. Counting it would let one original
                    // signal escalate itself. The derivation is already stated on the finding.
                    if (f.DerivedFromFindingId is null) return true;
                    derivedSuppressed++;
                    return false;
                })
                .GroupBy(f => NormalizeTarget(f.Target));

            foreach (var g in groups)
            {
                var checks = g.Select(f => f.Check!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var phaseCount = g.Select(f => f.Group).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                if (checks.Count < 2 || phaseCount < 2) continue;

                var max = g.Max(f => f.Severity);
                var sev = max >= Severity.Critical ? Severity.Critical : (Severity)((int)max + 1);
                var contributors = g.OrderBy(f => f.Id, StringComparer.Ordinal).Select(f => f.Id).ToList();
                emitted++;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId("correlation", g.Key, string.Join(",", checks)),
                    Severity = sev,
                    Description = $"Independent checks from {phaseCount} phases agree on this target " +
                                  $"({string.Join(", ", checks)}); contributing finding ids: " +
                                  $"{string.Join(", ", contributors)}. Severity raised one step above " +
                                  "the highest contributor; the original findings are unchanged.",
                    Target = g.First().Target,
                    Group = "correlation",
                    Check = "EVTX-CORR",
                    FixAction = FixAction.None,
                });
            }

            sink.Completed(Phase, check,
                $"{emitted} correlation finding(s) across {collector.Findings.Count} collected finding(s)" +
                (derivedSuppressed > 0
                    ? $"; {derivedSuppressed} escalation-derived finding(s) excluded from corroboration " +
                      "(they exist because an earlier finding armed the indicator that found them)"
                    : ""));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, Crash(ex)); }
    }

    // ---------------------------------------------------------------- shared plumbing

    private readonly record struct Lookback(DateTime SinceUtc, string Label);

    private static Lookback Window(ScanContext ctx)
    {
        if (ctx.SinceUtc is DateTime s)
            return new Lookback(s, $"window: since {s:yyyy-MM-dd HH:mm}Z (--since)");
        var days = ctx.Depth >= ScanDepth.Deep ? 30 : 14;
        return new Lookback(DateTime.UtcNow.AddDays(-days), $"window: last {days} days (default for {ctx.Depth})");
    }

    /// <summary>Lightweight per-channel precondition probe. Returns null when the channel is
    /// enabled and openable, otherwise the Inconclusive reason (naming the channel).</summary>
    private static string? ProbeChannel(string channel)
    {
        try
        {
            using var cfg = new EventLogConfiguration(channel);
            if (!cfg.IsEnabled)
                return $"channel '{channel}' is DISABLED — the period cannot be assessed from it " +
                       "(a disabled log on a suspect host is itself a red flag)";
            return null;
        }
        catch (EventLogNotFoundException) { return $"channel '{channel}' does not exist on this system"; }
        catch (UnauthorizedAccessException) { return $"channel '{channel}': access denied (run the scan elevated)"; }
        catch (EventLogException ex) { return $"channel '{channel}': {ex.Message}"; }
    }

    /// <summary>Bounded read: XPath-filtered (never an unfiltered read of a large log),
    /// newest-first so a budget cut keeps the most recent events, one budget per walk.
    /// "No matching events" is a clean empty result; unreadable is Error.</summary>
    private static EvtResult QueryEvents(ScanContext ctx, string channel, string xpath, EnumerationBudget budget)
    {
        var r = new EvtResult();
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            while (true)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) { r.Truncated = true; break; }
                using var rec = reader.ReadEvent();
                if (rec is null) break;
                var e = Evt.Parse(rec);
                if (e is not null && ctx.WithinTimeWindow(e.TimeUtc)) r.Events.Add(e);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (EventLogNotFoundException) { r.Error = $"channel '{channel}' not found on this system"; }
        catch (UnauthorizedAccessException) { r.Error = $"channel '{channel}': access denied (run the scan elevated)"; }
        catch (EventLogException ex) { r.Error = $"channel '{channel}' unreadable: {ex.Message}"; }
        return r;
    }

    private static string XPathFor(int[] ids, DateTime sinceUtc)
    {
        var idExpr = string.Join(" or ", ids.Select(i => $"EventID={i}"));
        return $"*[System[({idExpr}) and TimeCreated[timediff(@SystemTime) <= {MsBack(sinceUtc)}]]]";
    }

    private static string XPathLogonTypes(DateTime sinceUtc) =>
        $"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= {MsBack(sinceUtc)}]] and " +
        "EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]";

    private static string XPathSuccessForAccount(string account, DateTime sinceUtc) =>
        $"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= {MsBack(sinceUtc)}]] and " +
        $"EventData[Data[@Name='TargetUserName']='{account}']]";

    private static long MsBack(DateTime sinceUtc) =>
        (long)Math.Max(60_000, (DateTime.UtcNow - sinceUtc).TotalMilliseconds);

    private sealed class EvtResult
    {
        public List<Evt> Events { get; } = new();
        public bool Truncated { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>One parsed event: named EventData/UserData values flattened into a
    /// case-insensitive dictionary, unnamed data values kept in order.</summary>
    private sealed class Evt
    {
        public int Id { get; private init; }
        public DateTime? TimeUtc { get; private init; }
        public string? Provider { get; private set; }
        public Dictionary<string, string> Data { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Unnamed { get; } = new();

        public static Evt? Parse(EventRecord rec)
        {
            try
            {
                var e = new Evt { Id = rec.Id, TimeUtc = rec.TimeCreated?.ToUniversalTime() };
                var xml = XElement.Parse(rec.ToXml());
                foreach (var el in xml.Descendants())
                {
                    if (el.Name.LocalName == "Provider")
                    {
                        e.Provider ??= el.Attribute("Name")?.Value;
                        continue;
                    }
                    if (el.HasElements) continue;
                    var name = el.Name.LocalName == "Data" ? el.Attribute("Name")?.Value : el.Name.LocalName;
                    var value = el.Value;
                    if (string.IsNullOrEmpty(name))
                    {
                        if (value.Length > 0) e.Unnamed.Add(value);
                    }
                    else if (value.Length > 0 && !e.Data.ContainsKey(name))
                    {
                        e.Data[name] = value;
                    }
                }
                return e;
            }
            catch
            {
                return null; // one unparseable record must not kill the walk
            }
        }
    }

    private sealed class PatternAgg
    {
        public required IndicatorEntry Ind { get; init; }
        public required string Example { get; init; }
        public DateTime? LastUtc { get; init; }
        public int Count { get; set; }
        public SortedSet<string> Targets { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private void Conclude(IFindingSink sink, string check, List<string> gaps, string coverage)
    {
        if (gaps.Count == 0) sink.Completed(Phase, check, coverage);
        else sink.Inconclusive(Phase, check, $"{coverage}; partial coverage: {string.Join("; ", gaps)}");
    }

    private static string Crash(Exception ex) => $"check crashed: {ex.GetType().Name}: {ex.Message}";

    private static string Get(Evt e, string key, string fallback = "") =>
        e.Data.TryGetValue(key, out var v) ? v : fallback;

    private static string JoinUser(string domain, string user) =>
        user.Length == 0 ? "unknown account" : domain.Length == 0 ? user : $@"{domain}\{user}";

    /// <summary>Event data fields that could not be resolved come through as a literal "-";
    /// that is an absent value, not a name.</summary>
    internal static string Clean(string value) =>
        value is "-" or "--" ? "" : value.Trim();

    /// <summary>Human-readable member identity: the name when Windows resolved one, the SID
    /// when it did not, and both when they are both available — so the operator can always act
    /// on the finding.</summary>
    internal static string Identify(string name, string sid)
    {
        if (name.Length > 0 && sid.Length > 0) return $"'{name}' ({sid})";
        if (name.Length > 0) return $"'{name}'";
        return sid.Length > 0 ? $"SID {sid}" : "(unidentified)";
    }

    /// <summary>Well-known SID families for principals the OS and installers manage rather
    /// than people: virtual service accounts (S-1-5-80), IIS app pools (S-1-5-82), Hyper-V VM
    /// accounts (S-1-5-83), and the window-manager/WinRM/font-host virtual users. Machine
    /// accounts end in '$'. Matched by SID, never by localized display name (same discipline
    /// as the ACL phase), with the name checked only as a fallback when no SID was logged.</summary>
    internal static bool IsMachinePrincipal(string sid, string name)
    {
        foreach (var prefix in MachinePrincipalSidPrefixes)
            if (sid.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;

        if (sid.Length > 0) return false; // a real SID that is not machine-managed settles it
        return name.EndsWith('$') ||
               name.StartsWith(@"NT SERVICE\", StringComparison.OrdinalIgnoreCase) ||
               name.StartsWith(@"IIS APPPOOL\", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] MachinePrincipalSidPrefixes =
    {
        "S-1-5-80-", "S-1-5-82-", "S-1-5-83-", "S-1-5-90-", "S-1-5-94-", "S-1-5-96-",
    };

    private static string FileName(string path)
    {
        try
        {
            var n = Path.GetFileName(path.Trim('"'));
            return n.Length > 0 ? n : path;
        }
        catch { return path; }
    }

    private static string Flat(string s) => s.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    private static string NormalizeTarget(string t) => t.Trim().Trim('"').TrimEnd('\\').ToLowerInvariant();

    /// <summary>An indicator flagged NeedsCorroboration can never alone justify above
    /// Possible (guide rule 5).</summary>
    private static Severity CapSeverity(IndicatorEntry i) =>
        i.NeedsCorroboration && i.Severity > Severity.Possible ? Severity.Possible : i.Severity;

    /// <summary>Operator-supplied IOC sets that apply to event text (guide rule 12).
    /// Returns the matched pattern, or null. Hits are always Possible / FixAction.None.</summary>
    private static string? MatchCustomText(ScanContext ctx, string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        foreach (var setName in CustomSets)
            foreach (var i in ctx.Signatures.Set(setName))
                if (i.Pattern.Length >= 4 && text.Contains(i.Pattern, StringComparison.OrdinalIgnoreCase))
                    return i.Pattern;
        return null;
    }

    private static readonly string[] CustomSets = { "custom.filenames", "custom.ips", "custom.domains" };

    private static bool IsPrivateOrLocal(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return true;
        var v = ip.Trim();
        if (v is "-" or "::" or "::1" or "0.0.0.0" or "localhost") return true;
        if (v.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) v = v[7..];
        if (v.StartsWith("127.") || v.StartsWith("10.") ||
            v.StartsWith("192.168.") || v.StartsWith("169.254.")) return true;
        if (v.StartsWith("fe80", StringComparison.OrdinalIgnoreCase) ||
            v.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||
            v.StartsWith("fd", StringComparison.OrdinalIgnoreCase)) return true;
        if (v.StartsWith("172."))
        {
            var parts = v.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var o) && o is >= 16 and <= 31) return true;
        }
        // Not an address at all (workstation name in the IpAddress field): don't call it public.
        return !v.Contains('.') && !v.Contains(':');
    }

    /// <summary>Read-only registry probe for the ScriptBlockLogging policy.</summary>
    private static bool ScriptBlockPolicyEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", writable: false);
            return key?.GetValue("EnableScriptBlockLogging") is int v && v == 1;
        }
        catch { return false; }
    }

    private HashSet<string>? _serviceNames; // registry key names + resolved display names

    /// <summary>Read-only existence probe for a service (EVTX-002 install-run-remove
    /// heuristic). The 7045 "ServiceName" field is the DISPLAY name, so match against key
    /// names AND DisplayName values, and finally fall back to "does the ImagePath binary
    /// still exist on disk". Errs toward "exists" so a failed read never claims removal.</summary>
    private bool ServiceExists(string name, string image)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        try
        {
            if (_serviceNames is null)
            {
                _serviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using var services = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (services is null) return true; // can't enumerate — never claim removal
                foreach (var keyName in services.GetSubKeyNames())
                {
                    _serviceNames.Add(keyName);
                    try
                    {
                        using var sk = services.OpenSubKey(keyName, writable: false);
                        if (sk?.GetValue("DisplayName") is string dn && dn.Length > 0 && !dn.StartsWith('@'))
                            _serviceNames.Add(dn);
                    }
                    catch { /* one unreadable service key is not evidence of anything */ }
                }
            }
            if (_serviceNames.Contains(name)) return true;
            return ImageFileExists(image);
        }
        catch { return true; }
    }

    /// <summary>Best-effort check that a service ImagePath's binary is still on disk.
    /// Returns true (exists) on any doubt.</summary>
    private static bool ImageFileExists(string image)
    {
        try
        {
            var p = image.Trim();
            if (p.Length == 0) return true;
            if (p.StartsWith('"'))
            {
                var end = p.IndexOf('"', 1);
                p = end > 1 ? p[1..end] : p.Trim('"');
            }
            else
            {
                // Unquoted: strip arguments after the first extension-bearing token.
                var idx = p.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) idx = p.IndexOf(".sys ", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0) p = p[..(idx + 4)];
            }
            p = p.Replace('/', '\\');
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
            var root = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                p = Path.Combine(root, p[12..]);
            else if (p.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase) ||
                     p.StartsWith("syswow64\\", StringComparison.OrdinalIgnoreCase))
                p = Path.Combine(root, p);
            p = Environment.ExpandEnvironmentVariables(p);
            if (!Path.IsPathRooted(p)) return true; // can't resolve — never claim removal
            return File.Exists(p);
        }
        catch { return true; }
    }
}
