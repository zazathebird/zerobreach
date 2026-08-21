// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Profiles;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Util;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 3 — Command &amp; Control / RAT detection (spec §3 "Command &amp; control / RAT").
///
/// Dual-use is the defining problem of this phase: an RMM agent, a reverse proxy and a
/// tunneling client look identical to a legitimate deployment of the same tool. Rule applied
/// throughout: anything whose maliciousness depends on context, not content, caps at
/// POSSIBLE (INFO when vendor-trusted) with FixAction.None — "flag but don't auto-act".
/// Only inherently attacker-specific artifacts (known C2 named-pipe shapes, a known-bad IP)
/// go higher. All indicator content lives in Signatures/c2.json, never inline here.
/// </summary>
public sealed class C2Scanner : IScanner
{
    public int Phase => 3;
    public string Name => "C2 / Remote Access";
    public string Group => "C2";
    public ScanDepth MinDepth => ScanDepth.Quick;

    private const string PipePrefix = @"\\.\pipe\";

    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string WindowsTempDir = Path.Combine(WindowsDir, "Temp");
    private static readonly string System32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string ProgramFilesDir = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86Dir = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string ProgramDataDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private readonly Dictionary<int, (string Name, string? Path)> _procCache = new();
    private readonly Dictionary<string, SigState> _sigCache = new(StringComparer.OrdinalIgnoreCase);

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        CheckNamedPipes(ctx, sink);              // C2-001
        CheckNetworkConnections(ctx, sink);      // C2-002
        CheckBeaconPeriodicity(ctx, sink);       // C2-003 (FULL)
        CheckRmmTooling(ctx, sink);              // C2-004
        CheckTunnelingTools(ctx, sink);          // C2-005
        CheckImplantConfigResidue(ctx, sink);    // C2-006 (FULL)
        CheckHostResolutionTampering(ctx, sink); // C2-007
    }

    // ---------------------------------------------------------------- C2-001 named pipes

    private void CheckNamedPipes(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-001 named-pipe scan";
        try
        {
            var indicators = ctx.Signatures.Set("c2.named_pipes");
            if (indicators.Count == 0)
            {
                sink.Inconclusive(Phase, check, "no c2.named_pipes indicators loaded — pipe names not evaluated");
                return;
            }

            string[] pipes;
            try
            {
                // The .NET call enumerates the pipe namespace reliably; failure here means
                // the whole check could not look, which is never "clean".
                pipes = Directory.GetFiles(PipePrefix);
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"pipe namespace enumeration failed: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            foreach (var fullName in pipes)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var pipeName = fullName.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase)
                    ? fullName[PipePrefix.Length..] : fullName;

                foreach (var ind in indicators)
                {
                    if (!ind.Matches(pipeName)) continue;

                    // Owner attribution is best-effort and only attempted for matched pipes.
                    var ownerPid = PipeOwner.TryGetServerPid(PipePrefix + pipeName);
                    string? ownerPath = null;
                    var ownerName = "unknown";
                    if (ownerPid > 0)
                        (ownerName, ownerPath) = GetProcessInfo(ownerPid);

                    var severity = ind.Severity;
                    if (ind.NeedsCorroboration && severity > Severity.Possible)
                        severity = Severity.Possible;
                    // Attacker-specific pipe + owner outside System32 = active implant shape.
                    if (severity >= Severity.High && ownerPath is not null &&
                        !ownerPath.StartsWith(System32Dir, StringComparison.OrdinalIgnoreCase))
                        severity = Severity.Critical;

                    // kill_process only when the owning image is itself user-writable;
                    // otherwise tell the operator what to inspect instead.
                    var fix = FixAction.None;
                    string? fixParam = null;
                    if (ownerPid > 0 && ownerPath is not null && IsUserWritablePath(ownerPath))
                    {
                        fix = FixAction.KillProcess;
                        fixParam = $"{ownerPid}:{ownerName}";
                    }

                    var ownerDesc = ownerPid > 0
                        ? $"owning process PID {ownerPid} ({ownerName}, image: {ownerPath ?? "image path unavailable"})"
                        : "owning process could not be resolved — inspect with 'handle.exe -a -p * | findstr pipe' or Sysinternals PipeList";

                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, PipePrefix + pipeName, $"pipe:{pipeName}:{ownerPath ?? "unknown"}"),
                        Severity = severity,
                        Description = $"Named pipe '{pipeName}' matches a documented C2/remote-exec pipe pattern " +
                                      $"({ind.Note ?? ind.Pattern}); {ownerDesc}.",
                        Target = PipePrefix + pipeName,
                        FixAction = fix,
                        FixParam = fixParam,
                        Mitre = ind.Mitre,
                        Group = Group,
                        VendorTrusted = ctx.Signatures.IsVendorTrusted(ownerPath),
                        Check = check,
                    });
                    break; // first matching indicator wins for this pipe
                }
            }
            sink.Completed(Phase, check, $"{pipes.Length} pipes evaluated");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // -------------------------------------------------------- C2-002 network connections

    private void CheckNetworkConnections(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-002 tcp connections";
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] conns;
            IPEndPoint[] listeners;
            try
            {
                conns = props.GetActiveTcpConnections();
                listeners = props.GetActiveTcpListeners();
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"TCP table enumeration failed: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            var table = TcpTable.TryGet(); // PID attribution; null when the extended table is unavailable
            var attribution = table is not null;
            var pidByConn = new Dictionary<string, int>(StringComparer.Ordinal);
            var pidByListen = new Dictionary<string, int>(StringComparer.Ordinal);
            if (table is not null)
            {
                foreach (var r in table)
                {
                    if (r.State == TcpTable.StateListen)
                        pidByListen[$"{r.Local}:{r.LocalPort}"] = r.Pid;
                    else
                        pidByConn[$"{r.Local}:{r.LocalPort}|{r.Remote}:{r.RemotePort}"] = r.Pid;
                }
            }

            var c2Ips = ctx.Signatures.Set("c2.c2_ips");
            var customIps = ctx.Signatures.Set("custom.ips");
            var tunnelPorts = ctx.Signatures.Set("c2.tunnel_ports");
            var standardPorts = ctx.Signatures.Set("c2.standard_listen_ports");

            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(45));
            var establishedRemotes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var conn in conns)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;
                if (conn.State != TcpState.Established) continue;

                var remote = conn.RemoteEndPoint;
                var local = conn.LocalEndPoint;
                var pid = pidByConn.TryGetValue($"{Norm(local.Address)}:{local.Port}|{Norm(remote.Address)}:{remote.Port}", out var p) ? p : -1;

                string? ownerPath = null;
                var ownerName = "unknown";
                if (pid > 0) (ownerName, ownerPath) = GetProcessInfo(pid);

                var remoteIp = Norm(remote.Address);
                var isInternal = IsInternalAddress(remote.Address);
                if (!isInternal) establishedRemotes.Add(remoteIp);
                var trusted = ctx.Signatures.IsVendorTrusted(ownerPath);
                // Discriminator per catalog: owner image + remote addr + remote port + proto —
                // never the PID, never the ephemeral local port.
                var discBase = $"tcp:{ownerPath ?? "unknown"}:{remoteIp}:{remote.Port}";

                if (!isInternal)
                {
                    // Known C2 endpoint (set ships empty; populated by operator feeds) — CRITICAL.
                    var c2Hit = c2Ips.FirstOrDefault(i => i.Matches(remoteIp));
                    if (c2Hit is not null)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, remoteIp, discBase + ":c2ip"),
                            Severity = Severity.Critical,
                            Description = $"Established connection to {remoteIp}:{remote.Port}, which is on the known-C2 IP list " +
                                          $"({c2Hit.Note ?? c2Hit.Pattern}). Owner: {DescribeOwner(pid, ownerName, ownerPath)}.",
                            Target = ownerPath ?? $"{remoteIp}:{remote.Port}",
                            FixAction = pid > 0 && ownerPath is not null && IsUserWritablePath(ownerPath) ? FixAction.KillProcess : FixAction.None,
                            FixParam = pid > 0 && ownerPath is not null && IsUserWritablePath(ownerPath) ? $"{pid}:{ownerName}" : null,
                            Mitre = c2Hit.Mitre ?? new MitreRef("T1071", "Application Layer Protocol", "Command and Control"),
                            Group = Group,
                            VendorTrusted = trusted,
                            Check = check,
                        });
                    }

                    // Operator-supplied IOC (spec §6.6): POSSIBLE, never a destructive fix.
                    var iocHit = customIps.FirstOrDefault(i => i.Matches(remoteIp));
                    if (iocHit is not null)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, remoteIp, discBase + ":customip"),
                            Severity = Severity.Possible,
                            Description = $"Established connection to {remoteIp}:{remote.Port} matching a custom IOC " +
                                          $"({iocHit.Note ?? "operator-supplied IP"}). Custom IOCs are low-precision; confirm before acting. " +
                                          $"Owner: {DescribeOwner(pid, ownerName, ownerPath)}.",
                            Target = ownerPath ?? $"{remoteIp}:{remote.Port}",
                            FixAction = FixAction.None,
                            Mitre = new MitreRef("T1071", "Application Layer Protocol", "Command and Control"),
                            Group = Group,
                            VendorTrusted = trusted,
                            Check = check,
                        });
                    }

                    // Process running from a user-writable path talking to an external host.
                    // Severity discipline: High needs corroboration — user-writable path PLUS
                    // no embedded signature. A signed binary in a profile dir (dev tools,
                    // per-user installers) is a single indicator: Possible.
                    if (ownerPath is not null && IsUserWritablePath(ownerPath))
                    {
                        var sig = GetSigState(ownerPath);
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, ownerPath, discBase + ":userwritable"),
                            Severity = sig == SigState.NoEmbeddedSignature ? Severity.High : Severity.Possible,
                            Description = $"Process in a user-writable location has an established external connection: " +
                                          $"{ownerPath} (PID {pid}) -> {remoteIp}:{remote.Port}. {DescribeSig(sig)}. " +
                                          (sig == SigState.NoEmbeddedSignature
                                              ? "Unsigned binary in a user-writable path with external traffic is a corroborated C2 shape. "
                                              : "Single indicator only (path); the signature state does not corroborate. ") +
                                          "Verify the binary before acting; if malicious, quarantine the file after killing the process.",
                            Target = ownerPath,
                            FixAction = FixAction.None,
                            Mitre = new MitreRef("T1071", "Application Layer Protocol", "Command and Control"),
                            Group = Group,
                            VendorTrusted = trusted,
                            Check = check,
                        });
                    }

                    // Classic tunneler port + no embedded signature on the owner.
                    var portHit = tunnelPorts.FirstOrDefault(i => i.Matches(remote.Port.ToString(CultureInfo.InvariantCulture)));
                    if (portHit is not null && ownerPath is not null && IsUnsignedEvidence(ownerPath))
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, ownerPath, discBase + ":tunnelport"),
                            Severity = Severity.Possible,
                            Description = $"Connection to {remoteIp}:{remote.Port} ({portHit.Note ?? "port classically used by tunneling tooling"}) " +
                                          $"from {ownerPath} (PID {pid}), which has no embedded Authenticode signature (catalog signing not verified). " +
                                          "Dual-use signal — needs operator judgment.",
                            Target = ownerPath,
                            FixAction = FixAction.None,
                            Mitre = portHit.Mitre ?? new MitreRef("T1571", "Non-Standard Port", "Command and Control"),
                            Group = Group,
                            VendorTrusted = trusted,
                            Check = check,
                        });
                    }
                }
                else if (ownerPath is not null && IsUnsignedEvidence(ownerPath))
                {
                    // Internal/loopback peers are excluded from external-C2 logic but still
                    // reported at INFO when the owner is unsigned.
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, ownerPath, discBase + ":internal-unsigned"),
                        Severity = Severity.Info,
                        Description = $"Process without an embedded Authenticode signature has an internal/loopback connection: " +
                                      $"{ownerPath} (PID {pid}) -> {remoteIp}:{remote.Port}. Context only — internal peers are excluded from C2 heuristics.",
                        Target = ownerPath,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1071", "Application Layer Protocol", "Command and Control"),
                        Group = Group,
                        VendorTrusted = trusted,
                        Check = check,
                    });
                }
            }

            // Wildcard listeners on non-standard, non-ephemeral ports with unsigned owners.
            foreach (var listener in listeners)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;
                var isWildcard = listener.Address.Equals(IPAddress.Any) || listener.Address.Equals(IPAddress.IPv6Any);
                if (!isWildcard || listener.Port >= 49152) continue;
                if (standardPorts.Any(i => i.Matches(listener.Port.ToString(CultureInfo.InvariantCulture)))) continue;

                var pid = pidByListen.TryGetValue($"{Norm(listener.Address)}:{listener.Port}", out var lp) ? lp : -1;
                if (pid <= 0) continue; // no attribution -> covered by the attribution caveat below
                var (ownerName, ownerPath) = GetProcessInfo(pid);
                if (ownerPath is null || !IsUnsignedEvidence(ownerPath)) continue;

                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, ownerPath, $"tcplisten:{ownerPath}:{listener.Port}"),
                    Severity = Severity.High,
                    Description = $"Listener bound to all interfaces on non-standard port {listener.Port} by {ownerPath} " +
                                  $"(PID {pid}, {ownerName}). {DescribeSig(GetSigState(ownerPath))}. Possible bind shell / implant listener; verify the binary.",
                    Target = ownerPath,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1571", "Non-Standard Port", "Command and Control"),
                    Group = Group,
                    VendorTrusted = ctx.Signatures.IsVendorTrusted(ownerPath),
                    Check = check,
                });
            }

            if (!attribution)
                sink.Inconclusive(Phase, check,
                    "PID attribution unavailable (GetExtendedTcpTable failed) — only address/port IOC matching was performed; " +
                    "owner-based heuristics (user-writable path, unsigned listener) did not run");
            else
                sink.CompleteOrInconclusive(Phase, check, budget,
                    $"{conns.Length} connections / {listeners.Length} listeners");

            CheckCustomDomainIocs(ctx, sink, establishedRemotes);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>custom.domains IOCs vs the DNS client cache, correlated with currently
    /// established external remotes. Runs only when the operator supplied domain IOCs.</summary>
    private void CheckCustomDomainIocs(ScanContext ctx, IFindingSink sink, HashSet<string> establishedRemotes)
    {
        const string check = "C2-002 custom-domain IOCs";
        var customDomains = ctx.Signatures.Set("custom.domains");
        if (customDomains.Count == 0) return; // nothing to look for — no status needed

        try
        {
            var entries = new List<(string Name, string Data)>();
            using (var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
                       "SELECT Name, Data FROM MSFT_DNSClientCache"))
            {
                foreach (var obj in searcher.Get())
                {
                    using (obj)
                    {
                        var name = obj["Name"] as string ?? "";
                        var data = obj["Data"] as string ?? "";
                        if (name.Length > 0) entries.Add((name, data));
                    }
                }
            }

            foreach (var (name, data) in entries)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                foreach (var ioc in customDomains)
                {
                    var hit = ioc.Matches(name) ||
                              name.EndsWith("." + ioc.Pattern, StringComparison.OrdinalIgnoreCase);
                    if (!hit) continue;

                    var live = data.Length > 0 && establishedRemotes.Contains(data);
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, name, $"customdomain:{name}:{ioc.Pattern}"),
                        Severity = Severity.Possible,
                        Description = $"DNS client cache contains '{name}' matching custom IOC domain '{ioc.Pattern}'" +
                                      (live ? $"; the cached address {data} has a currently ESTABLISHED connection from this host."
                                            : $" (cached data: {(data.Length > 0 ? data : "n/a")})." ) +
                                      " Custom IOCs are low-precision; confirm before acting.",
                        Target = name,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
                        Group = Group,
                        Check = check,
                    });
                    break;
                }
            }
            sink.Completed(Phase, check, $"{entries.Count} DNS cache entries vs {customDomains.Count} domain IOCs");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check,
                $"DNS client cache unavailable — custom domain IOCs not checked ({ex.GetType().Name}: {ex.Message})");
        }
    }

    // ------------------------------------------------------- C2-003 beacon periodicity

    private void CheckBeaconPeriodicity(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-003 dns beacon periodicity";
        const string channel = "Microsoft-Windows-DNS-Client/Operational";
        try
        {
            if (ctx.Depth < ScanDepth.Full)
            {
                sink.Skipped(Phase, check, "requires FULL depth");
                return;
            }

            try
            {
                using var cfg = new EventLogConfiguration(channel);
                if (!cfg.IsEnabled)
                {
                    sink.Inconclusive(Phase, check, $"no DNS telemetry source enabled ({channel} is disabled)");
                    return;
                }
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"no DNS telemetry source enabled ({channel} unreadable: {ex.GetType().Name})");
                return;
            }

            var thresholds = ParseThresholds(ctx, "c2.beacon_thresholds");
            var minQueries = (int)thresholds.GetValueOrDefault("min_queries", 8);
            var maxCv = thresholds.GetValueOrDefault("max_cv", 0.20);
            var minSpanSeconds = thresholds.GetValueOrDefault("min_span_seconds", 600);
            var exclusions = ctx.Signatures.Set("c2.beacon_exclusions");

            var byDomain = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
            var budget = ctx.CreateBudget(20000, TimeSpan.FromSeconds(60));
            var total = 0;

            // --since bound embedded in the XPath: without it the enumeration budget burns
            // on out-of-window events before the post-filter below can drop them, starving
            // the in-window portion of the log. The WithinTimeWindow post-filter stays as a
            // safety net (timediff granularity, clock skew).
            var xpath = "*[System[(EventID=3006)]]";
            if (ctx.SinceUtc is not null)
            {
                var ms = (long)Math.Max(0, (DateTime.UtcNow - ctx.SinceUtc.Value).TotalMilliseconds);
                xpath = $"*[System[(EventID=3006) and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
            }
            var query = new EventLogQuery(channel, PathType.LogName, xpath)
            {
                ReverseDirection = true,
            };
            using (var reader = new EventLogReader(query))
            {
                for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
                {
                    using (rec)
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        if (!budget.TryConsume()) break;
                        total++;

                        var when = rec.TimeCreated?.ToUniversalTime();
                        if (when is null || !ctx.WithinTimeWindow(when)) continue;
                        var domain = rec.Properties.Count > 0 ? rec.Properties[0].Value as string : null;
                        if (string.IsNullOrWhiteSpace(domain)) continue;
                        domain = domain.TrimEnd('.');
                        if (exclusions.Any(e => e.Matches(domain))) continue;

                        if (!byDomain.TryGetValue(domain, out var list))
                            byDomain[domain] = list = new List<DateTime>();
                        list.Add(when.Value);
                    }
                }
            }

            if (total < minQueries)
            {
                sink.Inconclusive(Phase, check,
                    $"insufficient DNS telemetry ({total} query events in {channel}) — periodicity cannot be assessed");
                return;
            }

            foreach (var (domain, times) in byDomain)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (times.Count < minQueries) continue;
                times.Sort();
                var span = (times[^1] - times[0]).TotalSeconds;
                if (span < minSpanSeconds) continue;

                var deltas = new double[times.Count - 1];
                for (var i = 1; i < times.Count; i++)
                    deltas[i - 1] = (times[i] - times[i - 1]).TotalSeconds;
                var mean = deltas.Average();
                if (mean <= 0) continue;
                var sd = Math.Sqrt(deltas.Sum(d => (d - mean) * (d - mean)) / deltas.Length);
                var cv = sd / mean;
                if (cv > maxCv) continue;

                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, domain, "beacon:" + domain),
                    Severity = Severity.Possible,
                    Description = $"DNS queries for '{domain}' show beacon-like regularity: {times.Count} queries over " +
                                  $"{span / 60:0} min, mean interval {mean:0.#}s, coefficient of variation {cv:0.###} " +
                                  $"(threshold {maxCv:0.##}). Known OS-update/telemetry/AV domains were excluded before analysis. " +
                                  "This is a lead for an analyst, not something to act on automatically.",
                    Target = domain,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
                    Group = Group,
                    Check = check,
                });
            }

            sink.CompleteOrInconclusive(Phase, check, budget, $"{total} DNS query events, {byDomain.Count} candidate domains");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ------------------------------------------------------------ C2-004 RMM tooling

    private void CheckRmmTooling(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-004 rmm inventory";
        try
        {
            var rmm = ctx.Signatures.Set("c2.rmm_tools");
            if (rmm.Count == 0)
            {
                sink.Inconclusive(Phase, check, "no c2.rmm_tools indicators loaded — RMM inventory not evaluated");
                return;
            }

            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(45));

            // Installed products — both registry views.
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstall is null) continue;
                    foreach (var sub in uninstall.GetSubKeyNames())
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        if (!budget.TryConsume()) break;
                        ReportRmmFromUninstallKey(ctx, sink, rmm, uninstall, sub, $"HKLM({view})", null, check);
                    }
                }
                catch (Exception ex)
                {
                    sink.Inconclusive(Phase, check, $"uninstall enumeration failed for {view}: {ex.GetType().Name}: {ex.Message}");
                }
            }

            // Services (registry read — includes stopped/disabled services).
            try
            {
                using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (services is not null)
                {
                    foreach (var svcName in services.GetSubKeyNames())
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        if (!budget.TryConsume()) break;
                        using var svc = services.OpenSubKey(svcName);
                        if (svc is null) continue;
                        var display = svc.GetValue("DisplayName") as string ?? "";
                        var imagePath = svc.GetValue("ImagePath") as string ?? "";
                        var ind = rmm.FirstOrDefault(i => i.Matches(svcName) || i.Matches(display) || i.Matches(imagePath));
                        if (ind is null) continue;
                        ReportRmmMatch(ctx, sink, ind, check,
                            target: $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            discriminator: $"service:{svcName}",
                            what: $"Service '{svcName}' ({(display.Length > 0 ? display : "no display name")}), ImagePath: {(imagePath.Length > 0 ? imagePath : "n/a")}",
                            pathForContext: imagePath.Trim('"'));
                    }
                }
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"service enumeration failed: {ex.GetType().Name}: {ex.Message}");
            }

            // Running processes.
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!budget.TryConsume()) break;
                    using (proc)
                    {
                        // Match on the snapshot name first; resolving MainModule for every
                        // process is prohibitively slow (protected-process retries).
                        var ind = rmm.FirstOrDefault(i => i.Matches(proc.ProcessName));
                        if (ind is null) continue;
                        var (name, path) = GetProcessInfo(proc.Id);
                        ReportRmmMatch(ctx, sink, ind, check,
                            target: path ?? name,
                            discriminator: $"process:{path ?? name}",
                            what: $"Running process '{name}' (PID {proc.Id}, image: {path ?? "unavailable"})",
                            pathForContext: path);
                    }
                }
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"process enumeration failed: {ex.GetType().Name}: {ex.Message}");
            }

            sink.CompleteOrInconclusive(Phase, check, budget, "machine-wide inventory");

            // Per-profile installs (per-user uninstall hive).
            foreach (var p in ctx.Profiles)
            {
                var profCheck = $"{check} (profile {p.UserName})";
                try
                {
                    using var hive = p.OpenHiveRoot();
                    if (hive is null)
                    {
                        sink.Skipped(Phase, profCheck, $"profile {p.UserName}: hive not mounted (run with --load-hives)");
                        continue;
                    }
                    var profBudget = ctx.CreateBudget(1000, TimeSpan.FromSeconds(15));
                    using var uninstall = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstall is not null)
                    {
                        foreach (var sub in uninstall.GetSubKeyNames())
                        {
                            ctx.Cancel.ThrowIfCancellationRequested();
                            if (!profBudget.TryConsume()) break;
                            ReportRmmFromUninstallKey(ctx, sink, rmm, uninstall, sub, $"HKU\\{p.HiveKeyName}", p, check);
                        }
                    }
                    sink.CompleteOrInconclusive(Phase, profCheck, profBudget, $"profile {p.UserName}");
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    sink.Inconclusive(Phase, profCheck, $"profile {p.UserName}: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void ReportRmmFromUninstallKey(ScanContext ctx, IFindingSink sink, IReadOnlyList<IndicatorEntry> rmm,
        RegistryKey uninstall, string subKeyName, string sourceTag, UserProfile? profile, string check)
    {
        using var key = uninstall.OpenSubKey(subKeyName);
        if (key is null) return;
        var displayName = key.GetValue("DisplayName") as string ?? "";
        var publisher = key.GetValue("Publisher") as string ?? "";
        var installLocation = key.GetValue("InstallLocation") as string ?? "";
        var displayIcon = key.GetValue("DisplayIcon") as string ?? "";
        var installDate = key.GetValue("InstallDate") as string ?? "";

        var ind = rmm.FirstOrDefault(i =>
            i.Matches(displayName) || i.Matches(publisher) || i.Matches(installLocation) ||
            i.Matches(displayIcon) || i.Matches(subKeyName));
        if (ind is null) return;

        var recent = "";
        if (ctx.SinceUtc is not null &&
            DateTime.TryParseExact(installDate, "yyyyMMdd", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var installed) &&
            installed >= ctx.SinceUtc.Value)
        {
            recent = $" Installed {installed:yyyy-MM-dd}, INSIDE the requested time window — verify a ticket/change record explains it.";
        }

        var scope = profile is null ? "" : $" (user profile {profile.UserName})";
        var disc = profile is null
            ? $"uninstall:{sourceTag}:{subKeyName}"
            : $"uninstall:{profile.Sid}:{subKeyName}";
        ReportRmmMatch(ctx, sink, ind, check,
            target: installLocation.Length > 0 ? installLocation : $"{sourceTag}\\...\\Uninstall\\{subKeyName}",
            discriminator: disc,
            what: $"Installed product '{(displayName.Length > 0 ? displayName : subKeyName)}'" +
                  (publisher.Length > 0 ? $" by {publisher}" : "") + scope +
                  (installLocation.Length > 0 ? $", location: {installLocation}" : "") + recent,
            pathForContext: installLocation);
    }

    private void ReportRmmMatch(ScanContext ctx, IFindingSink sink, IndicatorEntry ind, string check,
        string target, string discriminator, string what, string? pathForContext)
    {
        var trusted = ctx.Signatures.IsVendorTrusted(ind.Note) ||
                      ctx.Signatures.IsVendorTrusted(pathForContext) ||
                      ctx.Signatures.IsVendorTrusted(target) ||
                      ctx.Signatures.IsVendorTrusted(what);

        // Dual-use discipline: RMM caps at POSSIBLE; vendor-trusted reads INFO (fails the
        // auto-select gate by construction) but stays fully visible and manually actionable.
        var severity = trusted ? Severity.Info : Severity.Possible;
        var aggravator = pathForContext is not null && pathForContext.Length > 0 && IsUserWritablePath(pathForContext)
            ? " Runs from a user-writable path, which is unusual for a managed deployment."
            : "";

        sink.Report(new Finding
        {
            Id = Finding.ComputeId(Group, target, discriminator),
            Severity = severity,
            Description = $"{what} matches remote-access/RMM tooling ({ind.Note ?? ind.Pattern}). " +
                          (trusted
                              ? "The vendor is on the trusted soft-list: this is legitimate software that is ALSO commonly abused for hands-on-keyboard access. Confirm the deployment is expected."
                              : "Not on the vendor-trusted list. Confirm who installed it and why.") +
                          aggravator +
                          " Never auto-uninstall remote-access tooling — removing a legitimate MSP agent mid-engagement causes the outage the safety model exists to prevent.",
            Target = target,
            FixAction = FixAction.None,
            Mitre = ind.Mitre ?? new MitreRef("T1219", "Remote Access Software", "Command and Control"),
            Group = Group,
            VendorTrusted = trusted,
            Check = check,
        });
    }

    // -------------------------------------------------- C2-005 tunneling / proxy tooling

    private void CheckTunnelingTools(ScanContext ctx, IFindingSink sink)
    {
        CheckPortProxy(ctx, sink);
        CheckSshTunnelConfigs(ctx, sink);
        CheckTunnelProcesses(ctx, sink);
        if (ctx.Depth >= ScanDepth.Full)
            CheckTunnelFiles(ctx, sink);
        else
            sink.Skipped(Phase, "C2-005 tunnel tool files", "requires FULL depth");
    }

    private void CheckPortProxy(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-005 portproxy";
        try
        {
            // Read the backing registry key rather than shelling out to netsh, so the check
            // works regardless of netsh output localization.
            using var portProxy = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PortProxy");
            if (portProxy is null)
            {
                sink.Completed(Phase, check, "no PortProxy key — no port forwarding configured");
                return;
            }

            var entries = 0;
            foreach (var family in portProxy.GetSubKeyNames()) // v4tov4, v4tov6, v6tov4, v6tov6
            {
                using var famKey = portProxy.OpenSubKey(family);
                if (famKey is null) continue;
                foreach (var proto in famKey.GetSubKeyNames()) // tcp
                {
                    using var protoKey = famKey.OpenSubKey(proto);
                    if (protoKey is null) continue;
                    foreach (var valueName in protoKey.GetValueNames())
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        var forwardTo = protoKey.GetValue(valueName) as string ?? "";
                        entries++;

                        // valueName is "listenaddress/listenport"; data is "connectaddress/connectport".
                        var listenParts = valueName.Split('/');
                        var listenAddr = listenParts.Length > 0 ? listenParts[0] : valueName;
                        var listenPort = listenParts.Length > 1 ? listenParts[1] : "?";
                        var deleteCmd = $"netsh interface portproxy delete {family} listenaddress={listenAddr} listenport={listenPort}";

                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group,
                                $@"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\{family}\{proto}",
                                $"portproxy:{family}:{proto}:{valueName}:{forwardTo}"),
                            Severity = Severity.High,
                            Description = $"netsh portproxy forwarding is configured ({family}/{proto}): listen {valueName} -> connect {forwardTo}. " +
                                          "Port forwarding via portproxy is rarely legitimate on a workstation and is a common attacker pivot/relay. " +
                                          $"If unexpected, remove it manually with: {deleteCmd}",
                            Target = $@"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\{family}\{proto}\{valueName}",
                            FixAction = FixAction.None, // network config changes are for the operator to make deliberately
                            Mitre = new MitreRef("T1090", "Proxy", "Command and Control"),
                            Group = Group,
                            Check = check,
                        });
                    }
                }
            }
            sink.Completed(Phase, check, $"{entries} portproxy entries");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"PortProxy registry read failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void CheckSshTunnelConfigs(ScanContext ctx, IFindingSink sink)
    {
        var directives = ctx.Signatures.Set("c2.ssh_tunnel_directives");
        foreach (var p in ctx.Profiles)
        {
            var check = $"C2-005 ssh tunnel configs (profile {p.UserName})";
            try
            {
                var cfgPath = Path.Combine(p.ProfilePath, ".ssh", "config");
                if (!File.Exists(cfgPath))
                {
                    sink.Completed(Phase, check, "no ssh config present");
                    continue;
                }

                string[] lines;
                try
                {
                    lines = ReadBoundedLines(cfgPath, 64 * 1024);
                }
                catch (Exception ex)
                {
                    sink.Inconclusive(Phase, check, $"could not read {cfgPath}: {ex.GetType().Name}");
                    continue;
                }

                foreach (var ind in directives)
                {
                    var matches = lines.Where(l => !l.TrimStart().StartsWith('#') && ind.Matches(l)).ToList();
                    if (matches.Count == 0) continue;
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, cfgPath, $"sshconfig:{p.Sid}:{ind.Pattern}"),
                        Severity = Severity.Possible,
                        Description = $"OpenSSH client config for user {p.UserName} contains {matches.Count} '{ind.Pattern}' " +
                                      $"directive(s) ({ind.Note ?? "reverse-tunnel directive"}). First: \"{matches[0].Trim()}\". " +
                                      "SSH is dual-use — confirm the tunnel is expected before acting.",
                        Target = cfgPath,
                        FixAction = FixAction.None,
                        Mitre = ind.Mitre ?? new MitreRef("T1572", "Protocol Tunneling", "Command and Control"),
                        Group = Group,
                        Check = check,
                    });
                }
                sink.Completed(Phase, check, cfgPath);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private void CheckTunnelProcesses(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-005 tunnel processes";
        try
        {
            var tools = ctx.Signatures.Set("c2.tunnel_tools");
            if (tools.Count == 0)
            {
                sink.Inconclusive(Phase, check, "no c2.tunnel_tools indicators loaded");
                return;
            }

            foreach (var proc in Process.GetProcesses())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                using (proc)
                {
                    // Snapshot name first — MainModule is resolved only for matches (slow
                    // for protected processes).
                    var ind = tools.FirstOrDefault(i => i.Matches(proc.ProcessName + ".exe"));
                    if (ind is null) continue;
                    var (name, path) = GetProcessInfo(proc.Id);
                    var exeName = path is not null ? Path.GetFileName(path) : proc.ProcessName + ".exe";

                    var nameOnly = ind.NeedsCorroboration
                        ? " Generic name — treat as a name match only until the binary is examined."
                        : "";
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, path ?? exeName, $"tunnelproc:{path ?? exeName}"),
                        Severity = Severity.Possible, // dual-use cap — never auto-act
                        Description = $"Running process '{name}' (PID {proc.Id}, image: {path ?? "unavailable"}) matches " +
                                      $"tunneling/proxy tooling ({ind.Note ?? ind.Pattern}). Dual-use: legitimate for admins and " +
                                      $"developers, also a standard attacker exfil/pivot channel.{nameOnly}",
                        Target = path ?? exeName,
                        FixAction = FixAction.None,
                        Mitre = ind.Mitre ?? new MitreRef("T1572", "Protocol Tunneling", "Command and Control"),
                        Group = Group,
                        VendorTrusted = ctx.Signatures.IsVendorTrusted(path),
                        Check = check,
                    });
                }
            }
            sink.Completed(Phase, check);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void CheckTunnelFiles(ScanContext ctx, IFindingSink sink)
    {
        var tools = ctx.Signatures.Set("c2.tunnel_tools");
        var content = ctx.Signatures.Set("c2.tunnel_content");
        var knownBad = ctx.Signatures.Set("c2.known_bad_hashes");
        var customHashes = ctx.Signatures.Set("custom.hashes");

        var walkTargets = new List<(string Scope, string CheckName, string[] Roots)>();
        foreach (var p in ctx.Profiles)
            walkTargets.Add(($"profile {p.UserName}", $"C2-005 tunnel tool files (profile {p.UserName})", UserWritableRoots(p.ProfilePath)));
        walkTargets.Add(("Public profile", "C2-005 tunnel tool files (Public)", UserWritableRoots(Path.Combine(Path.GetDirectoryName(WindowsDir) ?? @"C:\", "Users", "Public"))));

        foreach (var (scope, check, roots) in walkTargets)
        {
            try
            {
                var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(25));
                foreach (var file in WalkFiles(roots, budget, ctx.Cancel))
                {
                    var ind = tools.FirstOrDefault(i => i.Matches(file.Name));
                    if (ind is null) continue;
                    if (!ctx.WithinTimeWindow(SafeLastWriteUtc(file))) continue;

                    // Bounded content read to corroborate the name match. Cloud placeholders
                    // are never read — that would trigger a network hydration.
                    var placeholder = IsCloudPlaceholder(file);
                    var corroborations = new List<string>();
                    string? hash = null;
                    if (!placeholder)
                    {
                        var text = ReadBoundedText(file.FullName, 256 * 1024, 64 * 1024);
                        if (text is not null)
                            corroborations.AddRange(content.Where(c => c.Matches(text) ||
                                    text.Contains(c.Pattern, StringComparison.OrdinalIgnoreCase))
                                .Select(c => c.Note ?? c.Pattern));

                        // Hash checks: known-bad set ships empty in this build (no curated
                        // feed); custom.hashes comes from --ioc-file.
                        hash = FileHasher.Sha256(file.FullName);
                    }
                    var knownBadHit = hash is not null && knownBad.Any(h => h.Matches(hash));
                    var customHit = hash is not null && customHashes.Any(h => h.Matches(hash));

                    Severity severity;
                    FixAction fix;
                    string confidence;
                    if (knownBadHit)
                    {
                        severity = Severity.Critical;
                        fix = FixAction.Quarantine; // reversible even when hash-confirmed (§6.4 preference)
                        confidence = "SHA-256 matches the known-bad tunneler hash set.";
                    }
                    else if (corroborations.Count > 0)
                    {
                        severity = Severity.Possible; // dual-use cap — even a confirmed ngrok is not malware by itself
                        fix = FixAction.Quarantine;
                        confidence = $"Content corroborates the identification ({string.Join(", ", corroborations)}).";
                    }
                    else if (customHit)
                    {
                        severity = Severity.Possible;
                        fix = FixAction.Quarantine;
                        confidence = "SHA-256 matches an operator-supplied custom IOC hash (low-precision; confirm before acting).";
                    }
                    else
                    {
                        severity = Severity.Possible;
                        fix = FixAction.None;
                        confidence = placeholder
                            ? "Name match only — the file is a cloud placeholder, so its content was deliberately not read (reading would trigger a download)."
                            : ind.NeedsCorroboration
                                ? "Name match only on a generic filename — NOT corroborated; verify before treating as a tunneler."
                                : "Name match only — content markers were not found (renamed/packed builds evade this; absence is not exoneration).";
                    }

                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, file.FullName, $"tunnelfile:{file.FullName}:{ind.Pattern}"),
                        Severity = severity,
                        Description = $"File matching tunneling/proxy tooling ({ind.Note ?? ind.Pattern}) in {scope}: {file.FullName}. " +
                                      $"{confidence} Dual-use — flag but don't auto-act.",
                        Target = file.FullName,
                        FixAction = fix,
                        FixParam = fix == FixAction.Quarantine ? file.FullName : null,
                        Mitre = ind.Mitre ?? new MitreRef("T1572", "Protocol Tunneling", "Command and Control"),
                        Group = Group,
                        VendorTrusted = ctx.Signatures.IsVendorTrusted(file.FullName),
                        HashConfirmed = knownBadHit,
                        Check = check,
                    });
                }
                sink.CompleteOrInconclusive(Phase, check, budget, scope);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"{scope}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    // ---------------------------------------------- C2-006 implant config residue (FULL)

    private void CheckImplantConfigResidue(ScanContext ctx, IFindingSink sink)
    {
        if (ctx.Depth < ScanDepth.Full)
        {
            sink.Skipped(Phase, "C2-006 implant config residue", "requires FULL depth");
            return;
        }

        var shapeExt = ctx.Signatures.Set("c2.config_shape_ext");
        var carrierExt = ctx.Signatures.Set("c2.b64_carrier_ext");
        var thresholds = ParseThresholds(ctx, "c2.config_shape_thresholds");
        var minSize = (long)thresholds.GetValueOrDefault("min_size", 4096);
        var maxSize = (long)thresholds.GetValueOrDefault("max_size", 2 * 1024 * 1024);
        var minEntropy = thresholds.GetValueOrDefault("min_entropy", 7.4);
        var minB64 = (int)thresholds.GetValueOrDefault("min_b64_len", 512);
        var b64Regex = new Regex("[A-Za-z0-9+/]{" + minB64.ToString(CultureInfo.InvariantCulture) + ",}={0,2}",
            RegexOptions.Compiled, TimeSpan.FromSeconds(2));

        var walkTargets = new List<(string Scope, string CheckName, string[] Roots)>();
        foreach (var p in ctx.Profiles)
            walkTargets.Add(($"profile {p.UserName}", $"C2-006 implant config residue (profile {p.UserName})", UserWritableRoots(p.ProfilePath)));

        foreach (var (scope, check, roots) in walkTargets)
        {
            try
            {
                var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(25));
                foreach (var file in WalkFiles(roots, budget, ctx.Cancel))
                {
                    var len = SafeLength(file);
                    if (len <= 0 || len > 8 * 1024 * 1024) continue;
                    if (!ctx.WithinTimeWindow(SafeLastWriteUtc(file))) continue;
                    if (IsCloudPlaceholder(file)) continue; // content heuristics need a local read

                    var signals = new List<string>();

                    // Signal A: oversized base64 blob inside a script/shortcut carrier.
                    if (carrierExt.Any(e => e.Matches(file.Name)))
                    {
                        var text = ReadBoundedText(file.FullName, 64 * 1024, 0);
                        if (text is not null)
                        {
                            Match m;
                            try { m = b64Regex.Match(text); }
                            catch (RegexMatchTimeoutException) { m = Match.Empty; }
                            if (m.Success)
                            {
                                signals.Add($"base64 run of {m.Length} chars inside a {Path.GetExtension(file.Name)} carrier");
                                if (m.Value.StartsWith("TVq", StringComparison.Ordinal))
                                    signals.Add("the base64 blob decodes to an MZ (PE) header");
                            }
                        }
                    }

                    // Signal B: opaque high-entropy blob in the config-shape size band.
                    if (shapeExt.Any(e => e.Matches(file.Name)) && len >= minSize && len <= maxSize)
                    {
                        var bytes = ReadBoundedBytes(file.FullName, 64 * 1024);
                        if (bytes is { Length: > 0 } && !HasKnownBenignMagic(bytes))
                        {
                            var entropy = ShannonEntropy(bytes);
                            if (entropy >= minEntropy)
                                signals.Add($"high-entropy opaque content (entropy {entropy:0.##}/8.0, {len} bytes, no known file-format magic)");
                        }
                    }

                    if (signals.Count == 0) continue;

                    // Corroboration rule: one signal is a heuristic lead (POSSIBLE); two
                    // independent signals agreeing reach HIGH with a reversible fix.
                    var severity = signals.Count >= 2 ? Severity.High : Severity.Possible;
                    var fix = signals.Count >= 2 ? FixAction.Quarantine : FixAction.None;
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, file.FullName, "configresidue:" + file.FullName),
                        Severity = severity,
                        Description = $"Implant-config-residue heuristic hit in {scope}: {file.FullName} — " +
                                      string.Join("; ", signals) + ". " +
                                      (signals.Count >= 2
                                          ? "Two independent signals agree."
                                          : "Single heuristic signal only — this is a lead, not a confirmation.") +
                                      " Heuristic check: verify content before acting.",
                        Target = file.FullName,
                        FixAction = fix,
                        FixParam = fix == FixAction.Quarantine ? file.FullName : null,
                        Mitre = new MitreRef("T1027", "Obfuscated Files or Information", "Defense Evasion"),
                        Group = Group,
                        Check = check,
                    });
                }
                sink.CompleteOrInconclusive(Phase, check, budget, scope);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"{scope}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    // ------------------------------------ C2-007 host-resolution and proxy tampering

    private void CheckHostResolutionTampering(ScanContext ctx, IFindingSink sink)
    {
        CheckHostsFile(ctx, sink);
        CheckPerUserProxySettings(ctx, sink);
        CheckAdapterDnsServers(ctx, sink);
    }

    private void CheckHostsFile(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-007 hosts file";
        try
        {
            var hostsPath = Path.Combine(System32Dir, "drivers", "etc", "hosts");
            string[] lines;
            try
            {
                lines = File.ReadAllLines(hostsPath);
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"could not read {hostsPath}: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            var protectedDomains = ctx.Signatures.Set("c2.hosts_protected_domains");
            var customDomains = ctx.Signatures.Set("custom.domains");
            var mappings = 0;

            foreach (var raw in lines)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                var ip = parts[0];
                foreach (var host in parts.Skip(1))
                {
                    if (host.StartsWith('#')) break;
                    mappings++;

                    var prot = protectedDomains.FirstOrDefault(i => i.Matches(host));
                    if (prot is not null)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, hostsPath, $"hosts:{ip}:{host}"),
                            Severity = Severity.High,
                            Description = $"hosts file redirects '{host}' ({prot.Note ?? "security/update infrastructure"}) to {ip} — " +
                                          "a classic AV/update-blinding move. Review and remove the entry manually; " +
                                          "the scanner does not modify network configuration.",
                            Target = hostsPath,
                            FixAction = FixAction.None,
                            Mitre = prot.Mitre ?? new MitreRef("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
                            Group = Group,
                            Check = check,
                        });
                    }

                    var ioc = customDomains.FirstOrDefault(i =>
                        i.Matches(host) || host.EndsWith("." + i.Pattern, StringComparison.OrdinalIgnoreCase));
                    if (ioc is not null)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, hostsPath, $"hosts-ioc:{ip}:{host}"),
                            Severity = Severity.Possible,
                            Description = $"hosts file maps '{host}' (matches custom IOC domain '{ioc.Pattern}') to {ip}. " +
                                          "Custom IOCs are low-precision; confirm before acting.",
                            Target = hostsPath,
                            FixAction = FixAction.None,
                            Mitre = new MitreRef("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
                            Group = Group,
                            Check = check,
                        });
                    }
                }
            }
            sink.Completed(Phase, check, $"{mappings} active mappings evaluated");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void CheckPerUserProxySettings(ScanContext ctx, IFindingSink sink)
    {
        foreach (var p in ctx.Profiles)
        {
            var check = $"C2-007 proxy settings (profile {p.UserName})";
            try
            {
                using var hive = p.OpenHiveRoot();
                if (hive is null)
                {
                    sink.Skipped(Phase, check, $"profile {p.UserName}: hive not mounted (run with --load-hives)");
                    continue;
                }

                const string subPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
                var keyPath = $@"HKU\{p.HiveKeyName}\{subPath}";
                using var key = hive.OpenSubKey(subPath);
                if (key is null)
                {
                    sink.Completed(Phase, check, "no Internet Settings key");
                    continue;
                }

                var autoConfig = key.GetValue("AutoConfigURL") as string ?? "";
                var proxyServer = key.GetValue("ProxyServer") as string ?? "";
                var proxyEnable = key.GetValue("ProxyEnable") as int? ?? 0;

                if (autoConfig.Length > 0)
                {
                    // A PAC URL pointing at a raw IP is a classic traffic-hijack shape.
                    var rawIp = Regex.IsMatch(autoConfig, @"^https?://\d{1,3}(\.\d{1,3}){3}([:/]|$)",
                        RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, keyPath, $"proxy:{p.Sid}:AutoConfigURL:{autoConfig}"),
                        Severity = rawIp ? Severity.High : Severity.Possible,
                        Description = $"User {p.UserName} has a proxy auto-config URL set: {autoConfig}" +
                                      (rawIp ? " — the PAC URL points at a RAW IP address, which is a classic traffic-interception setup."
                                             : " — verify this is the expected corporate PAC location.") +
                                      " All user traffic can be routed through an attacker proxy via this value. " +
                                      "Network configuration changes are for the operator to make deliberately.",
                        Target = keyPath,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1090", "Proxy", "Command and Control"),
                        Group = Group,
                        Check = check,
                    });
                }

                if (proxyServer.Length > 0 && proxyEnable == 1)
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, keyPath, $"proxy:{p.Sid}:ProxyServer:{proxyServer}"),
                        Severity = Severity.Possible,
                        Description = $"User {p.UserName} has an enabled manual proxy: {proxyServer}. " +
                                      "Verify it matches the expected corporate proxy; an unexpected proxy routes all traffic " +
                                      "through a third party. Network configuration changes are for the operator to make deliberately.",
                        Target = keyPath,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1090", "Proxy", "Command and Control"),
                        Group = Group,
                        Check = check,
                    });
                }

                sink.Completed(Phase, check, keyPath);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private void CheckAdapterDnsServers(ScanContext ctx, IFindingSink sink)
    {
        const string check = "C2-007 adapter dns";
        try
        {
            var wellKnown = ctx.Signatures.Set("c2.wellknown_dns");
            var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    var ip = Norm(dns);
                    if (IsInternalAddress(dns)) continue; // LAN/DHCP-typical resolver
                    if (wellKnown.Any(w => w.Matches(ip))) continue;
                    if (!reported.Add($"{nic.Name}:{ip}")) continue;

                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, nic.Name, $"dnsserver:{nic.Id}:{ip}"),
                        Severity = Severity.Possible,
                        Description = $"Adapter '{nic.Name}' uses DNS server {ip}, which is neither a private/DHCP-typical " +
                                      "LAN resolver nor a well-known public resolver. Rogue DNS servers enable silent traffic " +
                                      "redirection (DNSChanger-style). Verify against the expected network configuration.",
                        Target = nic.Name,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1557", "Adversary-in-the-Middle", "Credential Access"),
                        Group = Group,
                        Check = check,
                    });
                }
            }
            sink.Completed(Phase, check);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ shared helpers

    private (string Name, string? Path) GetProcessInfo(int pid)
    {
        if (_procCache.TryGetValue(pid, out var cached)) return cached;
        var name = "unknown";
        string? path = null;
        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName;
            try { path = proc.MainModule?.FileName; }
            catch { /* protected/64-vs-32 process — image path unavailable */ }
        }
        catch { /* process exited or access denied */ }
        return _procCache[pid] = (name, path);
    }

    private static string DescribeOwner(int pid, string name, string? path) =>
        pid > 0 ? $"PID {pid} ({name}, image: {path ?? "unavailable"})" : "owning process could not be attributed";

    private enum SigState { SignedEmbedded, NoEmbeddedSignature, CheckFailed }

    /// <summary>Embedded Authenticode presence only. Distinguishes "no embedded signature"
    /// from "signature could not be checked"; catalog signing is NOT verified, so callers
    /// must not claim "unsigned" for OS files (guide rule 15).</summary>
    private SigState GetSigState(string path)
    {
        if (_sigCache.TryGetValue(path, out var cached)) return cached;
        SigState state;
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(path);
            state = SigState.SignedEmbedded;
        }
        catch (CryptographicException)
        {
            state = SigState.NoEmbeddedSignature;
        }
        catch
        {
            state = SigState.CheckFailed;
        }
        return _sigCache[path] = state;
    }

    private static string DescribeSig(SigState state) => state switch
    {
        SigState.SignedEmbedded => "The image carries an embedded Authenticode signature (validity not chained here)",
        SigState.NoEmbeddedSignature => "The image has no embedded Authenticode signature (catalog signing not verified)",
        _ => "The image's signature state could not be checked (this is not the same as unsigned)",
    };

    /// <summary>"Unsigned" evidence per guide rule 15: only asserted for images outside the
    /// Windows directory (OS files are routinely catalog-signed with no embedded signature).</summary>
    private bool IsUnsignedEvidence(string path) =>
        !path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase) &&
        GetSigState(path) == SigState.NoEmbeddedSignature;

    private static bool IsUserWritablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Trim('"');
        if (p.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase)) return false;
        if (p.StartsWith(ProgramFilesDir, StringComparison.OrdinalIgnoreCase)) return false;
        if (ProgramFilesX86Dir.Length > 0 && p.StartsWith(ProgramFilesX86Dir, StringComparison.OrdinalIgnoreCase)) return false;
        return p.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase)
               || p.StartsWith(ProgramDataDir, StringComparison.OrdinalIgnoreCase)
               || p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInternalAddress(IPAddress? addr)
    {
        if (addr is null) return true;
        if (IPAddress.IsLoopback(addr)) return true;
        if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any)) return true;
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return true;
            var first = addr.GetAddressBytes()[0];
            return (first & 0xFE) == 0xFC; // fc00::/7 unique local
        }
        var b = addr.GetAddressBytes();
        return b[0] == 10
               || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
               || (b[0] == 192 && b[1] == 168)
               || (b[0] == 169 && b[1] == 254)
               || (b[0] == 100 && b[1] >= 64 && b[1] <= 127); // CGNAT
    }

    private static string Norm(IPAddress? addr)
    {
        if (addr is null) return "";
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        var s = addr.ToString();
        var pct = s.IndexOf('%');
        return pct >= 0 ? s[..pct] : s;
    }

    private static Dictionary<string, double> ParseThresholds(ScanContext ctx, string setName)
    {
        var result = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in ctx.Signatures.Set(setName))
        foreach (var pair in entry.Pattern.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && double.TryParse(kv[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var v))
                result[kv[0].Trim()] = v;
        }
        return result;
    }

    private static string[] UserWritableRoots(string profilePath) => new[]
    {
        Path.Combine(profilePath, "AppData", "Local", "Temp"),
        Path.Combine(profilePath, "Downloads"),
        Path.Combine(profilePath, "Desktop"),
        Path.Combine(profilePath, "AppData", "Roaming"),
    };

    /// <summary>Budgeted, reparse-point-safe, depth-limited file walk. Per-directory errors
    /// are swallowed (access denied on one subtree must not kill the walk); the budget latch
    /// is what surfaces incompleteness via CompleteOrInconclusive.</summary>
    private static IEnumerable<FileInfo> WalkFiles(string[] roots, EnumerationBudget budget, CancellationToken cancel, int maxDepth = 4)
    {
        var stack = new Stack<(DirectoryInfo Dir, int Depth)>();
        foreach (var root in roots)
        {
            var di = new DirectoryInfo(root);
            if (di.Exists) stack.Push((di, 0));
        }

        while (stack.Count > 0)
        {
            cancel.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();

            FileInfo[] files;
            DirectoryInfo[] subs;
            try
            {
                files = dir.GetFiles();
                subs = depth < maxDepth ? dir.GetDirectories() : Array.Empty<DirectoryInfo>();
            }
            catch
            {
                continue;
            }

            foreach (var f in files)
            {
                if (!budget.TryConsume()) yield break;
                yield return f;
            }
            foreach (var sub in subs)
            {
                if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                stack.Push((sub, depth + 1));
            }
        }
    }

    /// <summary>Cloud-placeholder detection (OneDrive files-on-demand etc.). Reading the
    /// content of such a file triggers a network hydration — a scanner must never cause
    /// that, so content reads are skipped for placeholders.</summary>
    private static bool IsCloudPlaceholder(FileInfo f)
    {
        const FileAttributes recallOnOpen = (FileAttributes)0x00040000;
        const FileAttributes recallOnDataAccess = (FileAttributes)0x00400000;
        try
        {
            var attr = f.Attributes;
            return (attr & (FileAttributes.Offline | recallOnOpen | recallOnDataAccess)) != 0;
        }
        catch
        {
            return true; // can't tell — do not risk a hydration read
        }
    }

    private static DateTime? SafeLastWriteUtc(FileInfo f)
    {
        try { return f.LastWriteTimeUtc; }
        catch { return null; }
    }

    private static long SafeLength(FileInfo f)
    {
        try { return f.Length; }
        catch { return -1; }
    }

    private static byte[]? ReadBoundedBytes(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buf = new byte[Math.Min(maxBytes, (int)Math.Min(fs.Length, int.MaxValue))];
            var read = 0;
            while (read < buf.Length)
            {
                var n = fs.Read(buf, read, buf.Length - read);
                if (n == 0) break;
                read += n;
            }
            return read == buf.Length ? buf : buf.AsSpan(0, read).ToArray();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Bounded text view of a file: head (and optional tail) bytes decoded as
    /// latin-1 plus a UTF-16LE view, so wide-string constants are matchable too.</summary>
    private static string? ReadBoundedText(string path, int headBytes, int tailBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var head = new byte[(int)Math.Min(fs.Length, headBytes)];
            _ = fs.Read(head, 0, head.Length);
            byte[] tail = Array.Empty<byte>();
            if (tailBytes > 0 && fs.Length > headBytes + tailBytes)
            {
                fs.Seek(-tailBytes, SeekOrigin.End);
                tail = new byte[tailBytes];
                _ = fs.Read(tail, 0, tail.Length);
            }
            var latin = Encoding.Latin1.GetString(head) + Encoding.Latin1.GetString(tail);
            var wide = Encoding.Unicode.GetString(head) + Encoding.Unicode.GetString(tail);
            return latin + "\n" + wide;
        }
        catch
        {
            return null;
        }
    }

    private static string[] ReadBoundedLines(string path, int maxBytes)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        var buf = new byte[(int)Math.Min(fs.Length, maxBytes)];
        _ = fs.Read(buf, 0, buf.Length);
        return Encoding.UTF8.GetString(buf).Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
    }

    private static double ShannonEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var counts = new int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            var pr = (double)c / data.Length;
            entropy -= pr * Math.Log2(pr);
        }
        return entropy;
    }

    /// <summary>Benign file-format magic prefixes excluded from the high-entropy heuristic
    /// (compressed/media/database formats are legitimately high-entropy). Structural
    /// constants, not indicators-of-badness, so they may live in code.</summary>
    private static bool HasKnownBenignMagic(byte[] head)
    {
        if (head.Length < 4) return false;
        ReadOnlySpan<byte> h = head;
        return StartsWith(h, new byte[] { 0x50, 0x4B, 0x03, 0x04 })    // zip/office
            || StartsWith(h, "MZ"u8)
            || StartsWith(h, new byte[] { 0x89, 0x50, 0x4E, 0x47 })    // png
            || StartsWith(h, new byte[] { 0xFF, 0xD8, 0xFF }) || StartsWith(h, "GIF8"u8)
            || StartsWith(h, "%PDF"u8) || StartsWith(h, "Rar!"u8)
            || StartsWith(h, new byte[] { 0x37, 0x7A, 0xBC, 0xAF }) // 7z
            || StartsWith(h, new byte[] { 0x1F, 0x8B })             // gzip
            || StartsWith(h, "SQLite format 3"u8)
            || StartsWith(h, new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }) // OLE compound
            || StartsWith(h, "OggS"u8) || StartsWith(h, "fLaC"u8)
            || StartsWith(h, new byte[] { 0x00, 0x00, 0x00 });      // many media containers (ftyp boxes)
    }

    private static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> prefix) =>
        data.Length >= prefix.Length && data[..prefix.Length].SequenceEqual(prefix);

    // ---------------------------------------------------------------- P/Invoke helpers

    /// <summary>Owning-PID resolution for named pipes. Only invoked for pipes that already
    /// matched a C2 indicator (opening a pipe consumes a client instance, so it is kept to
    /// the minimum). Query-only access; nothing is read from or written to the pipe.</summary>
    private static class PipeOwner
    {
        private const uint FileReadAttributes = 0x0080;
        private const uint ShareReadWrite = 0x0003;
        private const uint OpenExisting = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe, out uint serverProcessId);

        public static int TryGetServerPid(string pipePath)
        {
            try
            {
                using var handle = CreateFileW(pipePath, FileReadAttributes, ShareReadWrite,
                    IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
                if (handle.IsInvalid) return -1;
                return GetNamedPipeServerProcessId(handle, out var pid) ? (int)pid : -1;
            }
            catch
            {
                return -1;
            }
        }
    }

    /// <summary>PID attribution for TCP endpoints via GetExtendedTcpTable (the one small
    /// P/Invoke helper the architecture allows for this). Read-only system query.</summary>
    private static class TcpTable
    {
        public const int StateListen = 2;

        public sealed record Row(string Local, int LocalPort, string Remote, int RemotePort, int State, int Pid);

        private const int AfInet = 2;
        private const int AfInet6 = 23;
        private const int TcpTableOwnerPidAll = 5;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int size,
            [MarshalAs(UnmanagedType.Bool)] bool sort, int ipVersion, int tableClass, uint reserved);

        public static List<Row>? TryGet()
        {
            try
            {
                var rows = new List<Row>();
                if (!ReadTable(AfInet, rows)) return null;
                ReadTable(AfInet6, rows); // v6 failure alone doesn't void v4 attribution
                return rows;
            }
            catch
            {
                return null;
            }
        }

        private static bool ReadTable(int family, List<Row> rows)
        {
            var size = 0;
            _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidAll, 0);
            if (size <= 0) return false;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0) != 0)
                    return false;
                var count = Marshal.ReadInt32(buffer);
                var rowPtr = buffer + 4;
                var rowSize = family == AfInet ? 24 : 56;
                for (var i = 0; i < count; i++, rowPtr += rowSize)
                {
                    rows.Add(family == AfInet ? ParseV4(rowPtr) : ParseV6(rowPtr));
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Row ParseV4(IntPtr p)
        {
            var state = Marshal.ReadInt32(p, 0);
            var local = new IPAddress((uint)Marshal.ReadInt32(p, 4));
            var localPort = DecodePort(Marshal.ReadInt32(p, 8));
            var remote = new IPAddress((uint)Marshal.ReadInt32(p, 12));
            var remotePort = DecodePort(Marshal.ReadInt32(p, 16));
            var pid = Marshal.ReadInt32(p, 20);
            return new Row(Norm(local), localPort, Norm(remote), remotePort, state, pid);
        }

        private static Row ParseV6(IntPtr p)
        {
            var localBytes = new byte[16];
            Marshal.Copy(p, localBytes, 0, 16);
            var localPort = DecodePort(Marshal.ReadInt32(p, 20));
            var remoteBytes = new byte[16];
            Marshal.Copy(p + 24, remoteBytes, 0, 16);
            var remotePort = DecodePort(Marshal.ReadInt32(p, 44));
            var state = Marshal.ReadInt32(p, 48);
            var pid = Marshal.ReadInt32(p, 52);
            return new Row(Norm(new IPAddress(localBytes)), localPort,
                Norm(new IPAddress(remoteBytes)), remotePort, state, pid);
        }

        private static int DecodePort(int networkOrderDword) =>
            ((networkOrderDword & 0xFF) << 8) | ((networkOrderDword >> 8) & 0xFF);
    }
}
