// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Scythe.Core.Model;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;

namespace Scythe.Scanners;

/// <summary>
/// Phase 8 — Permission / ACL integrity (spec §3 "Permission/ACL integrity").
/// Compares ACLs and owners of high-value filesystem/registry locations against
/// STRUCTURAL expectations: broad low-privilege principals (Everyone, Authenticated
/// Users, BUILTIN\Users, ...) must never hold write/control rights on system paths,
/// service binaries, service registry keys, or startup-adjacent directories, and
/// protected OS paths must be owned by TrustedInstaller / Administrators / SYSTEM.
/// Principals are matched by well-known SID, never by localized account name.
/// Strictly read-only: every finding is FixAction.None (or a display-only Info
/// RunCommand) — ACL repair via icacls has real blast radius and stays a deliberate
/// operator action, so the recommended command is shown in the description only.
/// </summary>
public sealed class AclIntegrityScanner : IScanner
{
    public int Phase => 8;
    public string Name => "Permission / ACL Integrity";
    public string Group => "AclIntegrity";
    public ScanDepth MinDepth => ScanDepth.Deep;

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        CheckSystemPathAcls(ctx, sink);        // ACL-001
        CheckServicePermissions(ctx, sink);    // ACL-002
        CheckUnquotedServicePaths(ctx, sink);  // ACL-003
        CheckStartupDirPermissions(ctx, sink); // ACL-004
        ReportBaselineDelegated(sink);         // ACL-005
    }

    // ---------------------------------------------------------------- principals / masks

    /// <summary>Broad low-privilege principals that must never hold write/control rights
    /// on protected paths. Matched by well-known SID — locale-independent.</summary>
    private static readonly (SecurityIdentifier Sid, string Label)[] LowPrivPrincipals =
    {
        (new SecurityIdentifier(WellKnownSidType.WorldSid, null), "Everyone"),
        (new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), "Authenticated Users"),
        (new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), @"BUILTIN\Users"),
        (new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null), @"BUILTIN\Guests"),
        (new SecurityIdentifier(WellKnownSidType.AnonymousSid, null), "ANONYMOUS LOGON"),
        (new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), "INTERACTIVE"),
    };

    /// <summary>NT SERVICE\TrustedInstaller — a well-known service SID (constant on every
    /// Windows install), not covered by WellKnownSidType.</summary>
    private static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    private static readonly SecurityIdentifier AdminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    private const FileSystemRights FileWriteMask =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private const FileSystemRights DirWriteMask =
        FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    /// <summary>For directories where user file-creation is a documented Windows DEFAULT
    /// (%ProgramData% root, %SystemRoot%\Tasks): flagging CreateFiles there would false-
    /// positive on every healthy machine, so only control-plane rights are anomalous.</summary>
    private const FileSystemRights DirControlMask =
        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>Planting a hijack binary in an interception directory needs file-create.</summary>
    private const FileSystemRights InterceptMask = FileSystemRights.CreateFiles;

    private const RegistryRights RegWriteMask =
        RegistryRights.SetValue | RegistryRights.CreateSubKey | RegistryRights.Delete |
        RegistryRights.ChangePermissions | RegistryRights.TakeOwnership;

    private static readonly HashSet<string> UserCreateIsWindowsDefault = new(StringComparer.OrdinalIgnoreCase)
    {
        Environment.ExpandEnvironmentVariables("%ProgramData%"),
        Environment.ExpandEnvironmentVariables(@"%SystemRoot%\Tasks"),
        // Stock ACL grants Authenticated Users (CI)(W,Rc) — the Task Scheduler service
        // impersonates callers when registering tasks. Only control-plane rights are drift.
        Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\Tasks"),
    };

    // ---------------------------------------------------------------- ACL-001

    /// <summary>ACL-001: audit a fixed set of high-value directories and binaries
    /// (from aclintegrity.system_dirs / aclintegrity.system_binaries) for write grants to
    /// broad principals (HIGH — direct privilege-escalation primitive) and for owners
    /// outside TrustedInstaller/Administrators/SYSTEM (POSSIBLE).</summary>
    private void CheckSystemPathAcls(ScanContext ctx, IFindingSink sink)
    {
        const string check = "ACL-001 system path ACL drift";
        try
        {
            var targets = new List<(IndicatorEntry Entry, bool IsDir)>();
            foreach (var e in ctx.Signatures.Set("aclintegrity.system_dirs")) targets.Add((e, true));
            foreach (var e in ctx.Signatures.Set("aclintegrity.system_binaries")) targets.Add((e, false));
            if (targets.Count == 0)
            {
                sink.Inconclusive(Phase, check,
                    "signature sets aclintegrity.system_dirs / aclintegrity.system_binaries are empty — nothing audited");
                return;
            }

            var budget = ctx.CreateBudget(64, TimeSpan.FromSeconds(30));
            int examined = 0, missing = 0, unreadable = 0;

            foreach (var (entry, isDir) in targets)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;

                var path = Environment.ExpandEnvironmentVariables(entry.Pattern);
                if (path.Contains('%')) { missing++; continue; } // env var not defined on this SKU
                if (isDir ? !Directory.Exists(path) : !File.Exists(path)) { missing++; continue; }

                FileSystemSecurity sec;
                try
                {
                    sec = isDir
                        ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
                        : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                }
                catch (OperationCanceledException) { throw; }
                catch { unreadable++; continue; }
                examined++;

                var mask = !isDir ? FileWriteMask
                    : UserCreateIsWindowsDefault.Contains(path) ? DirControlMask : DirWriteMask;

                foreach (var (label, sidVal, rights) in BroadWritableAces(sec, mask))
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, path, $"ACL-001:write:{sidVal}"),
                        Severity = entry.Severity,
                        Group = Group,
                        Check = check,
                        Target = path,
                        Description = $"Protected system {(isDir ? "directory" : "binary")} grants write access to a " +
                                      $"low-privileged principal: {label} ({sidVal}) holds {DescribeFileRights(rights, isDir)}. " +
                                      $"Any local user can plant or replace code that runs with elevated privileges" +
                                      (entry.Note is null ? "" : $" ({entry.Note})") + ". " +
                                      $"Review by hand: icacls \"{path}\" — ACL repair (e.g. icacls /remove:g) has real " +
                                      $"blast radius and is an operator decision; the engine will not modify ACLs.",
                        FixAction = FixAction.None,
                        Mitre = entry.Mitre ?? new MitreRef("T1222.001", "Windows File and Directory Permissions Modification", "Defense Evasion"),
                    });
                }

                if (sec.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !IsApprovedOwner(owner))
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, path, $"ACL-001:owner:{owner.Value}"),
                        Severity = Severity.Possible,
                        Group = Group,
                        Check = check,
                        Target = path,
                        Description = $"Unexpected owner on protected system {(isDir ? "directory" : "binary")}: " +
                                      $"{DisplaySid(owner)}. Expected NT SERVICE\\TrustedInstaller, BUILTIN\\Administrators " +
                                      $"or NT AUTHORITY\\SYSTEM. An owner can rewrite the ACL at will, so ownership drift " +
                                      $"often precedes a file swap. Review by hand: icacls \"{path}\" — no automatic remediation.",
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1222.001", "Windows File and Directory Permissions Modification", "Defense Evasion"),
                    });
                }
            }

            if (budget.Exhausted)
                sink.Inconclusive(Phase, check, $"walk cut short: {budget.ExhaustedReason} ({examined} of {targets.Count} targets audited)");
            else if (unreadable > 0)
                sink.Inconclusive(Phase, check, $"{unreadable} of {targets.Count} targets had unreadable ACLs ({examined} audited, {missing} not present)");
            else
                sink.Completed(Phase, check, $"{examined} system paths audited ({missing} not present on this system)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- ACL-002

    /// <summary>ACL-002: every service — is the resolved ImagePath binary writable by a
    /// broad low-privilege principal, and is the service's registry key writable by one.
    /// Either is HIGH (T1574.010 / T1574.011).</summary>
    private void CheckServicePermissions(ScanContext ctx, IFindingSink sink)
    {
        const string check = "ACL-002 service binary and service key permissions";
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (services is null)
            {
                sink.Inconclusive(Phase, check, @"cannot open HKLM\SYSTEM\CurrentControlSet\Services");
                return;
            }

            var budget = ctx.CreateBudget(2500, TimeSpan.FromSeconds(120));
            int examined = 0, unreadableKeys = 0, unreadableFiles = 0;
            var binariesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var svcName in services.GetSubKeyNames())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;

                var keyPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}";
                try
                {
                    using var sk = services.OpenSubKey(svcName, writable: false);
                    if (sk is null) { unreadableKeys++; continue; }
                    examined++;

                    RegistrySecurity? regSec = null;
                    try { regSec = sk.GetAccessControl(AccessControlSections.Access); }
                    catch (OperationCanceledException) { throw; }
                    catch { unreadableKeys++; }

                    if (regSec is not null)
                    {
                        foreach (var (label, sidVal, rights) in BroadWritableRegAces(regSec))
                        {
                            sink.Report(new Finding
                            {
                                Id = Finding.ComputeId(Group, keyPath, $"ACL-002:regwrite:{sidVal}"),
                                Severity = Severity.High,
                                Group = Group,
                                Check = check,
                                Target = keyPath,
                                Description = $"Service registry key writable by low-privileged principal: {label} ({sidVal}) " +
                                              $"holds {DescribeRegRights(rights)}. ImagePath or service parameters can be " +
                                              $"redirected to attacker code running as the service account. Review by hand: " +
                                              $"powershell -c \"Get-Acl 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{svcName}' | Format-List\" " +
                                              $"— ACL repair is an operator decision; the engine will not modify ACLs.",
                                FixAction = FixAction.None,
                                Mitre = new MitreRef("T1574.011", "Services Registry Permissions Weakness", "Privilege Escalation"),
                            });
                        }
                    }

                    var image = sk.GetValue("ImagePath") as string;
                    var binary = string.IsNullOrWhiteSpace(image) ? null : ResolveServiceBinary(image);
                    if (binary is not null && binariesSeen.Add(binary))
                    {
                        try
                        {
                            var fileSec = new FileInfo(binary).GetAccessControl(AccessControlSections.Access);
                            foreach (var (label, sidVal, rights) in BroadWritableAces(fileSec, FileWriteMask))
                            {
                                sink.Report(new Finding
                                {
                                    Id = Finding.ComputeId(Group, binary, $"ACL-002:filewrite:{sidVal}"),
                                    Severity = Severity.High,
                                    Group = Group,
                                    Check = check,
                                    Target = binary,
                                    Description = $"Service binary writable by low-privileged principal: {label} ({sidVal}) " +
                                                  $"holds {DescribeFileRights(rights, directory: false)} on \"{binary}\" " +
                                                  $"(first referencing service: {svcName}). Replacing the binary yields code " +
                                                  $"execution as the service account. Review by hand: icacls \"{binary}\" — " +
                                                  $"ACL repair is an operator decision; the engine will not modify ACLs.",
                                    FixAction = FixAction.None,
                                    Mitre = new MitreRef("T1574.010", "Services File Permissions Weakness", "Privilege Escalation"),
                                    VendorTrusted = ctx.Signatures.IsVendorTrusted(binary),
                                });
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch { unreadableFiles++; }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { unreadableKeys++; }
            }

            if (budget.Exhausted)
                sink.Inconclusive(Phase, check, $"walk cut short: {budget.ExhaustedReason} ({examined} services examined)");
            else if (unreadableKeys > 0 || unreadableFiles > 0)
                sink.Inconclusive(Phase, check,
                    $"{examined} services examined, but {unreadableKeys} service keys and {unreadableFiles} binaries had unreadable ACLs");
            else
                sink.Completed(Phase, check, $"{examined} services examined ({binariesSeen.Count} distinct binaries)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- ACL-003

    /// <summary>ACL-003: unquoted service paths — flagged HIGH only when an interception
    /// directory is actually creatable by a broad low-privilege principal (that precision is
    /// the point of the check); unquoted alone is INFO.</summary>
    private void CheckUnquotedServicePaths(ScanContext ctx, IFindingSink sink)
    {
        const string check = "ACL-003 unquoted service paths with writable interception points";
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (services is null)
            {
                sink.Inconclusive(Phase, check, @"cannot open HKLM\SYSTEM\CurrentControlSet\Services");
                return;
            }

            var budget = ctx.CreateBudget(2500, TimeSpan.FromSeconds(60));
            int examined = 0, unquoted = 0, unreadableKeys = 0, unreadableDirs = 0;
            var dirAclCache = new Dictionary<string, List<(string Label, string SidVal, FileSystemRights Rights)>?>(StringComparer.OrdinalIgnoreCase);

            foreach (var svcName in services.GetSubKeyNames())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;

                try
                {
                    using var sk = services.OpenSubKey(svcName, writable: false);
                    if (sk is null) { unreadableKeys++; continue; }
                    examined++;

                    if (sk.GetValue("ImagePath") is not string raw || string.IsNullOrWhiteSpace(raw)) continue;
                    var trimmed = raw.Trim();
                    if (trimmed.StartsWith('"')) continue; // properly quoted

                    var expanded = Environment.ExpandEnvironmentVariables(trimmed);
                    if (expanded.StartsWith(@"\??\", StringComparison.Ordinal)) expanded = expanded[4..];

                    // Only .exe paths go through CreateProcess word-splitting; kernel drivers don't.
                    var exeIdx = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                    if (exeIdx < 0) continue;
                    var pathPortion = expanded[..(exeIdx + 4)];
                    if (!pathPortion.Contains(' ')) continue;                      // no ambiguity
                    if (pathPortion.Length < 3 || pathPortion[1] != ':') continue; // not a drive-rooted path
                    unquoted++;

                    // Interception candidates: for "C:\Program Files\My App\svc.exe" Windows will
                    // try "C:\Program.exe" then "C:\Program Files\My.exe" first. Exploitable only
                    // when the directory that would hold the candidate is file-creatable.
                    var hits = new List<(string Dir, string Label, string SidVal, FileSystemRights Rights)>();
                    var seenDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < pathPortion.Length; i++)
                    {
                        if (pathPortion[i] != ' ') continue;
                        var dir = Path.GetDirectoryName(pathPortion[..i] + ".exe");
                        if (string.IsNullOrEmpty(dir) || !seenDirs.Add(dir)) continue;
                        if (!Directory.Exists(dir)) continue;

                        if (!dirAclCache.TryGetValue(dir, out var aces))
                        {
                            try
                            {
                                var sec = new DirectoryInfo(dir).GetAccessControl(AccessControlSections.Access);
                                aces = BroadWritableAces(sec, InterceptMask);
                            }
                            catch (OperationCanceledException) { throw; }
                            catch { aces = null; unreadableDirs++; }
                            dirAclCache[dir] = aces;
                        }
                        if (aces is null) continue;
                        foreach (var (label, sidVal, rights) in aces) hits.Add((dir, label, sidVal, rights));
                    }

                    if (hits.Count > 0)
                    {
                        foreach (var (dir, label, sidVal, _) in hits)
                        {
                            sink.Report(new Finding
                            {
                                Id = Finding.ComputeId(Group, pathPortion, $"ACL-003:{svcName}:{dir}:{sidVal}"),
                                Severity = Severity.High,
                                Group = Group,
                                Check = check,
                                Target = pathPortion,
                                Description = $"Unquoted service path for service '{svcName}' with a WRITABLE interception " +
                                              $"point: {label} ({sidVal}) can create files in \"{dir}\", so a planted " +
                                              $"executable there would be launched instead of the real binary next time the " +
                                              $"service starts. Fix by hand: quote the path " +
                                              $"(sc.exe config \"{svcName}\" binPath= \"\\\"{pathPortion}\\\"\" — preserve any " +
                                              $"arguments) or tighten the directory ACL (icacls \"{dir}\"). Operator decision; " +
                                              $"the engine will not modify services or ACLs.",
                                FixAction = FixAction.None,
                                Mitre = new MitreRef("T1574.009", "Path Interception by Unquoted Path", "Privilege Escalation"),
                            });
                        }
                    }
                    else
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, pathPortion, $"ACL-003:{svcName}:unquoted"),
                            Severity = Severity.Info,
                            Group = Group,
                            Check = check,
                            Target = pathPortion,
                            Description = $"Unquoted service path with spaces for service '{svcName}', but no interception " +
                                          $"directory creatable by a broad low-privilege principal was found" +
                                          (hitsUnreadableNote(seenDirs, dirAclCache)) +
                                          $" — hygiene issue, not a live escalation path. Consider quoting the path anyway.",
                            FixAction = FixAction.RunCommand,
                            FixParam = $"sc.exe qc \"{svcName}\"",
                            Mitre = new MitreRef("T1574.009", "Path Interception by Unquoted Path", "Privilege Escalation"),
                        });
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { unreadableKeys++; }
            }

            if (budget.Exhausted)
                sink.Inconclusive(Phase, check, $"walk cut short: {budget.ExhaustedReason} ({examined} services examined)");
            else if (unreadableKeys > 0 || unreadableDirs > 0)
                sink.Inconclusive(Phase, check,
                    $"{examined} services examined ({unquoted} unquoted-with-spaces), but {unreadableKeys} service keys and " +
                    $"{unreadableDirs} interception directories were unreadable");
            else
                sink.Completed(Phase, check, $"{examined} services examined, {unquoted} unquoted paths with spaces evaluated");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }

        static string hitsUnreadableNote(HashSet<string> seenDirs,
            Dictionary<string, List<(string, string, FileSystemRights)>?> cache)
        {
            var unreadable = seenDirs.Count(d => cache.TryGetValue(d, out var a) && a is null);
            return unreadable == 0 ? "" : $" ({unreadable} interception directories could not be read, so this is not conclusive)";
        }
    }

    // ---------------------------------------------------------------- ACL-004

    /// <summary>ACL-004: startup-adjacent directories (all-users Startup, Start Menu root,
    /// scheduled-task stores from aclintegrity.startup_dirs, plus each profile's own Startup
    /// folder) writable by broad low-privilege principals → HIGH persistence-planting
    /// primitive. Per-profile folders are filesystem-only, so every profile is walkable
    /// regardless of hive state.</summary>
    private void CheckStartupDirPermissions(ScanContext ctx, IFindingSink sink)
    {
        const string check = "ACL-004 startup-adjacent directory permissions";

        // System-wide targets (one walk).
        try
        {
            var entries = ctx.Signatures.Set("aclintegrity.startup_dirs");
            if (entries.Count == 0)
            {
                sink.Inconclusive(Phase, check, "signature set aclintegrity.startup_dirs is empty — nothing audited");
            }
            else
            {
                var budget = ctx.CreateBudget(16, TimeSpan.FromSeconds(15));
                int examined = 0, missing = 0, unreadable = 0;

                foreach (var entry in entries)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!budget.TryConsume()) break;

                    var path = Environment.ExpandEnvironmentVariables(entry.Pattern);
                    if (path.Contains('%') || !Directory.Exists(path)) { missing++; continue; }

                    var mask = UserCreateIsWindowsDefault.Contains(path) ? DirControlMask : DirWriteMask;
                    try
                    {
                        var sec = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
                        examined++;
                        foreach (var (label, sidVal, rights) in BroadWritableAces(sec, mask))
                        {
                            sink.Report(new Finding
                            {
                                Id = Finding.ComputeId(Group, path, $"ACL-004:write:{sidVal}"),
                                Severity = entry.Severity,
                                Group = Group,
                                Check = check,
                                Target = path,
                                Description = $"Startup-adjacent directory writable by low-privileged principal: {label} " +
                                              $"({sidVal}) holds {DescribeFileRights(rights, directory: true)}" +
                                              (entry.Note is null ? "" : $" ({entry.Note})") + ". Anything planted here " +
                                              $"executes automatically. Review by hand: icacls \"{path}\" — ACL repair is an " +
                                              $"operator decision; the engine will not modify ACLs.",
                                FixAction = FixAction.None,
                                Mitre = entry.Mitre ?? new MitreRef("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
                            });
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { unreadable++; }
                }

                if (budget.Exhausted)
                    sink.Inconclusive(Phase, check, $"walk cut short: {budget.ExhaustedReason} ({examined} system-wide targets audited)");
                else if (unreadable > 0)
                    sink.Inconclusive(Phase, check, $"{unreadable} of {entries.Count} system-wide targets had unreadable ACLs ({examined} audited)");
                else
                    sink.Completed(Phase, check, $"{examined} system-wide startup/task directories audited ({missing} not present)");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }

        // Per-profile Startup folders — fresh budget per profile (spec §4).
        foreach (var p in ctx.Profiles)
        {
            var profCheck = $"{check} (profiles)";
            try
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var budget = ctx.CreateBudget(8, TimeSpan.FromSeconds(10));
                var startup = Path.Combine(p.ProfilePath,
                    @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");

                if (!budget.TryConsume())
                {
                    sink.Inconclusive(Phase, profCheck, $"profile {p.UserName}: {budget.ExhaustedReason}");
                    continue;
                }
                if (!Directory.Exists(startup))
                {
                    sink.Completed(Phase, profCheck, $"profile {p.UserName}: no Startup folder present");
                    continue;
                }

                List<(string Label, string SidVal, FileSystemRights Rights)> aces;
                try
                {
                    var sec = new DirectoryInfo(startup).GetAccessControl(AccessControlSections.Access);
                    aces = BroadWritableAces(sec, DirWriteMask);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    sink.Inconclusive(Phase, profCheck, $"profile {p.UserName}: Startup folder ACL unreadable ({ex.GetType().Name})");
                    continue;
                }

                foreach (var (label, sidVal, rights) in aces)
                {
                    sink.Report(new Finding
                    {
                        // Profile SID in the discriminator: two users' identical folders are two findings.
                        Id = Finding.ComputeId(Group, startup, $"ACL-004:{p.Sid}:write:{sidVal}"),
                        Severity = Severity.High,
                        Group = Group,
                        Check = profCheck,
                        Target = startup,
                        Description = $"Startup folder of profile '{p.UserName}' grants write access to a broad principal " +
                                      $"beyond the profile owner: {label} ({sidVal}) holds " +
                                      $"{DescribeFileRights(rights, directory: true)}. Any local account can plant a " +
                                      $"program that runs at this user's next logon. Review by hand: icacls \"{startup}\" — " +
                                      $"ACL repair is an operator decision; the engine will not modify ACLs.",
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
                    });
                }

                sink.CompleteOrInconclusive(Phase, profCheck, budget, $"profile {p.UserName}");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, profCheck, $"profile {p.UserName}: check crashed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    // ---------------------------------------------------------------- ACL-005

    /// <summary>ACL-005 (catalog): persist an ACL baseline and diff on later runs. In this
    /// architecture scanners are strictly read-only (spec §6.1 — no file writes from a
    /// scanner), so the snapshot cannot be written here; drift detection is instead provided
    /// by the engine-level baseline-diff mode, which works because this scanner's finding ids
    /// are deterministic. Reported as Skipped, never silently absent (spec §6.7).</summary>
    private void ReportBaselineDelegated(IFindingSink sink)
    {
        sink.Skipped(Phase, "ACL-005 ACL baseline comparison",
            "not performed inside the scanner: scanners are read-only and cannot persist a baseline snapshot; " +
            "use the engine's baseline-diff mode (deterministic finding ids make ACL drift show up as new findings)");
    }

    // ---------------------------------------------------------------- ACE evaluation helpers

    /// <summary>Effective rights (allow minus deny, generic bits normalized) held by each
    /// broad low-privilege principal, intersected with <paramref name="mask"/>.</summary>
    private static List<(string Label, string SidVal, FileSystemRights Rights)> BroadWritableAces(
        FileSystemSecurity sec, FileSystemRights mask)
    {
        var results = new List<(string, string, FileSystemRights)>();
        var rules = sec.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));

        foreach (var (sid, label) in LowPrivPrincipals)
        {
            int allow = 0, deny = 0;
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.IdentityReference is not SecurityIdentifier rs || !rs.Equals(sid)) continue;
                if (rule.AccessControlType == AccessControlType.Allow) allow |= (int)rule.FileSystemRights;
                else deny |= (int)rule.FileSystemRights;
            }
            var effective = NormalizeFileRights(allow) & ~NormalizeFileRights(deny) & mask;
            if (effective != 0) results.Add((label, sid.Value, effective));
        }
        return results;
    }

    private static List<(string Label, string SidVal, RegistryRights Rights)> BroadWritableRegAces(RegistrySecurity sec)
    {
        var results = new List<(string, string, RegistryRights)>();
        var rules = sec.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));

        foreach (var (sid, label) in LowPrivPrincipals)
        {
            int allow = 0, deny = 0;
            foreach (RegistryAccessRule rule in rules)
            {
                if (rule.IdentityReference is not SecurityIdentifier rs || !rs.Equals(sid)) continue;
                if (rule.AccessControlType == AccessControlType.Allow) allow |= (int)rule.RegistryRights;
                else deny |= (int)rule.RegistryRights;
            }
            var effective = NormalizeRegRights(allow) & ~NormalizeRegRights(deny) & RegWriteMask;
            if (effective != 0) results.Add((label, sid.Value, effective));
        }
        return results;
    }

    /// <summary>Raw ACEs can carry generic rights that the enum cast hides — map
    /// GENERIC_ALL/GENERIC_WRITE onto their file-specific equivalents before masking.</summary>
    private static FileSystemRights NormalizeFileRights(int raw)
    {
        var v = unchecked((uint)raw);
        var r = (FileSystemRights)(v & 0x01FFFFFFu);
        if ((v & 0x10000000u) != 0) r |= FileSystemRights.FullControl; // GENERIC_ALL
        if ((v & 0x40000000u) != 0) r |= FileSystemRights.Write;       // GENERIC_WRITE
        return r;
    }

    private static RegistryRights NormalizeRegRights(int raw)
    {
        var v = unchecked((uint)raw);
        var r = (RegistryRights)(v & 0x001FFFFFu);
        if ((v & 0x10000000u) != 0) r |= RegistryRights.FullControl;                            // GENERIC_ALL
        if ((v & 0x40000000u) != 0) r |= RegistryRights.SetValue | RegistryRights.CreateSubKey; // GENERIC_WRITE → KEY_WRITE
        return r;
    }

    private static bool IsApprovedOwner(SecurityIdentifier owner) =>
        owner.Equals(TrustedInstallerSid) || owner.Equals(AdminsSid) || owner.Equals(SystemSid);

    private static string DisplaySid(SecurityIdentifier sid)
    {
        try { return $"{sid.Translate(typeof(NTAccount))} ({sid.Value})"; }
        catch { return sid.Value; }
    }

    private static string DescribeFileRights(FileSystemRights r, bool directory)
    {
        var parts = new List<string>(6);
        if ((r & FileSystemRights.WriteData) != 0) parts.Add(directory ? "CreateFiles" : "WriteData");
        if ((r & FileSystemRights.AppendData) != 0) parts.Add(directory ? "CreateDirectories" : "AppendData");
        if ((r & FileSystemRights.Delete) != 0) parts.Add("Delete");
        if (directory && (r & FileSystemRights.DeleteSubdirectoriesAndFiles) != 0) parts.Add("DeleteSubdirectoriesAndFiles");
        if ((r & FileSystemRights.ChangePermissions) != 0) parts.Add("ChangePermissions(WriteDACL)");
        if ((r & FileSystemRights.TakeOwnership) != 0) parts.Add("TakeOwnership");
        return parts.Count > 0 ? string.Join(", ", parts) : r.ToString();
    }

    private static string DescribeRegRights(RegistryRights r)
    {
        var parts = new List<string>(5);
        if ((r & RegistryRights.SetValue) != 0) parts.Add("SetValue");
        if ((r & RegistryRights.CreateSubKey) != 0) parts.Add("CreateSubKey");
        if ((r & RegistryRights.Delete) != 0) parts.Add("Delete");
        if ((r & RegistryRights.ChangePermissions) != 0) parts.Add("ChangePermissions(WriteDACL)");
        if ((r & RegistryRights.TakeOwnership) != 0) parts.Add("TakeOwnership");
        return parts.Count > 0 ? string.Join(", ", parts) : r.ToString();
    }

    // ---------------------------------------------------------------- path helpers

    /// <summary>Best-effort resolution of a service ImagePath command line to an on-disk
    /// binary, mirroring CreateProcess semantics for unquoted paths (progressively longer
    /// prefixes, first existing match wins) and normalizing NT-style prefixes.</summary>
    private static string? ResolveServiceBinary(string imagePath)
    {
        var s = imagePath.Trim();
        if (s.Length == 0) return null;

        if (s[0] == '"')
        {
            var end = s.IndexOf('"', 1);
            if (end <= 1) return null;
            var quoted = NormalizeNtPath(s[1..end]);
            return File.Exists(quoted) ? quoted : null;
        }

        var acc = "";
        foreach (var token in s.Split(' '))
        {
            acc = acc.Length == 0 ? token : $"{acc} {token}";
            var candidate = NormalizeNtPath(acc);
            if (candidate.Length == 0) continue;
            if (File.Exists(candidate)) return candidate;
            if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(candidate + ".exe"))
                return candidate + ".exe";
        }
        return null;
    }

    /// <summary>Expands env vars and normalizes \??\, \SystemRoot\ and bare
    /// "System32\drivers\x.sys"-style relative ImagePaths against the Windows directory.</summary>
    private static string NormalizeNtPath(string p)
    {
        p = Environment.ExpandEnvironmentVariables(p.Trim());
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(winDir, p[@"\SystemRoot\".Length..]);
        else if (p.Length > 2 && p[1] != ':' && p[0] != '\\')
            p = Path.Combine(winDir, p);
        return p;
    }
}
