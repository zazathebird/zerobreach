using System.Text;

namespace ZeroBreach.Paths;

/// <summary>
/// Normalises a Windows path string into a canonical comparison form, with a full audit trail.
/// Pure string logic: no file system, no current directory, no process environment. Environment
/// variables expand only from a caller-supplied dictionary. The model follows the documented
/// Win32 <c>GetFullPathName</c> normalisation rules (separator canonicalisation, relative-segment
/// resolution, per-segment and path-end dot/space trimming), with one deliberate divergence:
/// <c>\\?\</c>-prefixed paths, which Windows passes to the kernel verbatim, are still normalised
/// here so that the comparison form is useful — the <see cref="PathFlags.VerbatimPrefix"/> flag
/// preserves the fact that Windows itself would not have rewritten them.
/// </summary>
public static class PathNormalizer
{
    /// <summary>
    /// Normalise one path. Never throws for path content: malformed input returns
    /// <see cref="OperationState.Failed"/> with a reason — a guard must never be crashed by
    /// its input. Deterministic: same path and same dictionary always produce the same result.
    /// </summary>
    /// <param name="path">The path exactly as received.</param>
    /// <param name="environment">
    /// Variables for <c>%VAR%</c> expansion, looked up case-insensitively (Windows environment
    /// semantics). Null means no variables are defined. A reference to a variable that is not
    /// in the dictionary fails the whole normalisation: silently leaving <c>%SystemRoot%</c>
    /// literal would make the guard compare against text that is not a real path (fail-closed).
    /// </param>
    public static NormalizedPath Normalize(string path, IReadOnlyDictionary<string, string>? environment = null)
    {
        var transformations = new List<PathTransformation>();

        if (path is null)
            return NormalizedPath.Failure("", "path is null", transformations);
        if (path.Length == 0)
            return NormalizedPath.Failure(path, "path is empty", transformations);
        if (path.Length > PathLimits.MaxPathLength)
            return NormalizedPath.Failure(path, $"path is {path.Length} characters; the maximum is {PathLimits.MaxPathLength}", transformations);

        // ---- 1. environment expansion (caller-supplied dictionary only) ----------------------
        if (!TryExpandEnvironment(path, environment, transformations, out string s, out string? envError))
            return NormalizedPath.Failure(path, envError!, transformations);
        if (s.Length == 0)
            return NormalizedPath.Failure(path, "path is empty after environment expansion", transformations);
        if (s.Length > PathLimits.MaxPathLength)
            return NormalizedPath.Failure(path, $"path is {s.Length} characters after environment expansion; the maximum is {PathLimits.MaxPathLength}", transformations);

        PathFlags flags = PathFlags.None;

        // The verbatim flag reports what the caller literally wrote, so it is checked before
        // separator normalisation: //?/C:/x reaches the same namespace but is NOT a verbatim
        // path on real Windows (the prefix must be exactly backslashes to skip normalisation).
        if (s.StartsWith(@"\\?\", StringComparison.Ordinal))
            flags |= PathFlags.VerbatimPrefix;

        // ---- 2. separator direction ----------------------------------------------------------
        if (s.Contains('/'))
        {
            string before = s;
            s = s.Replace('/', '\\');
            transformations.Add(new PathTransformation(TransformationKind.SeparatorsNormalized, before, s));
        }

        // ---- 3. root / prefix parsing --------------------------------------------------------
        if (!TryParseRoot(s, out RootParse root, out string? rootError))
            return NormalizedPath.Failure(path, rootError!, transformations);

        // ---- 4. split into segments, collapsing duplicate separators -------------------------
        string rest = root.Rest;
        bool endedWithSep = rest.EndsWith('\\');
        var segments = new List<string>();
        int emptyCount = 0;
        if (rest.Length > 0)
        {
            foreach (string part in rest.Split('\\'))
            {
                if (part.Length == 0)
                    emptyCount++;
                else
                    segments.Add(part);
            }
            if (endedWithSep)
                emptyCount--; // the trailing empty is the trailing separator, not a duplicate
        }

        // UNC-family roots consume their server and share (and a device root its device name)
        // from the front of the segment list, so duplicated separators inside the root region
        // are collapsed by the same rule as everywhere else.
        if (root.ConsumeCount > 0)
        {
            if (segments.Count < 1 && root.ConsumeCount >= 1 && root.IsUnc)
                return NormalizedPath.Failure(path, "UNC path is missing a server name", transformations);
            if (segments.Count < 1)
                return NormalizedPath.Failure(path, "device namespace path is missing a device name", transformations);
            if (root.IsUnc && segments.Count < 2)
                return NormalizedPath.Failure(path, $"UNC path '\\\\{segments[0]}' is missing a share name", transformations);

            if (root.IsUnc)
            {
                string server = segments[0];
                string share = segments[1];
                segments.RemoveRange(0, 2);
                if (!ValidateRootComponent(server, "UNC server name", out string? e1))
                    return NormalizedPath.Failure(path, e1!, transformations);
                if (!ValidateRootComponent(share, "UNC share name", out string? e2))
                    return NormalizedPath.Failure(path, e2!, transformations);

                root.DisplayRoot = @"\\" + server + @"\" + share;
                root.CanonicalRoot = @"\\" + server.ToLowerInvariant() + @"\" + share.ToLowerInvariant();

                string serverLower = server.ToLowerInvariant();
                if (serverLower is "localhost" or "127.0.0.1")
                    flags |= PathFlags.LoopbackUncServer;
                if (share.EndsWith('$') &&
                    ((share.Length == 2 && char.IsAsciiLetter(share[0])) ||
                     share.Equals("admin$", StringComparison.OrdinalIgnoreCase)))
                    flags |= PathFlags.AdministrativeShare;
                if (CharacterSets.ContainsHomoglyphs(server) || CharacterSets.ContainsHomoglyphs(share))
                    flags |= PathFlags.HomoglyphCharacters;
            }
            else
            {
                string device = segments[0];
                segments.RemoveAt(0);
                if (!ValidateRootComponent(device, "device name", out string? e3))
                    return NormalizedPath.Failure(path, e3!, transformations);

                root.DisplayRoot = @"\\.\" + device;
                root.CanonicalRoot = @"\\.\" + device.ToLowerInvariant();
                if (CharacterSets.ContainsHomoglyphs(device))
                    flags |= PathFlags.HomoglyphCharacters;
            }
        }

        // Audit-trail snapshots. 'work' always holds the whole-path text at the current stage
        // boundary; each record's Before/After are consecutive values of it.
        string work = s;
        if (root.PrefixRewritten)
        {
            // The prefix-normalised text with the rest of the path untouched (duplicate
            // separators, if any, are still present — they are the next stage's business).
            string afterPrefix = PrefixNormalizedForm(root);
            transformations.Add(new PathTransformation(TransformationKind.PrefixNormalized, work, afterPrefix));
            work = afterPrefix;
        }
        if (emptyCount > 0)
        {
            string after = Rebuild(root, segments, endedWithSep, streamSuffix: null);
            if (!string.Equals(after, work, StringComparison.Ordinal))
                transformations.Add(new PathTransformation(TransformationKind.DuplicateSeparatorsCollapsed, work, after));
            work = after;
        }
        else
        {
            // No rewrite happened, but re-materialise so later stage snapshots are consistent.
            work = Rebuild(root, segments, endedWithSep, streamSuffix: null);
        }

        // ---- 5. resolve '.' and '..' segments ------------------------------------------------
        // Rooted forms clamp '..' at the root (Windows cannot climb above C:\ or \\server\share);
        // unrooted forms keep leading '..' because there is no root to clamp against.
        bool rooted = root.Kind is not (PathKind.Relative or PathKind.DriveRelative);
        bool dotsRemoved = false, parentsResolved = false, clamped = false;
        var resolved = new List<string>(segments.Count);
        foreach (string seg in segments)
        {
            if (seg == ".")
            {
                dotsRemoved = true;
                continue;
            }
            if (seg == "..")
            {
                if (resolved.Count > 0 && resolved[^1] != "..")
                {
                    resolved.RemoveAt(resolved.Count - 1);
                    parentsResolved = true;
                }
                else if (rooted)
                {
                    clamped = true; // '..' at the root is silently absorbed, but never silently: flagged below
                }
                else
                {
                    resolved.Add("..");
                }
                continue;
            }
            resolved.Add(seg);
        }
        if (dotsRemoved || parentsResolved || clamped)
        {
            string after = Rebuild(root, resolved, endedWithSep, streamSuffix: null);
            bool changed = !string.Equals(after, work, StringComparison.Ordinal);
            if (dotsRemoved && changed)
                transformations.Add(new PathTransformation(TransformationKind.DotSegmentsRemoved, work, after));
            if (parentsResolved && changed)
                transformations.Add(new PathTransformation(TransformationKind.ParentSegmentsResolved, work, after));
            if (clamped)
            {
                if (changed)
                    transformations.Add(new PathTransformation(TransformationKind.ParentTraversalClamped, work, after));
                flags |= PathFlags.ParentTraversalClamped;
            }
            work = after;
        }

        // ---- 6. trailing dots and spaces -----------------------------------------------------
        // Per the documented Win32 rules: a segment ending in exactly one '.' loses it ('a.' ->
        // 'a', but 'a..' and '...' are untouched — three or more dots is a legal name); and when
        // the path does NOT end in a separator, the final segment loses ALL trailing dots and
        // spaces. A trailing separator therefore protects a trailing-space name ("C:\a \" keeps
        // "a "), which is the only way such a directory can be addressed.
        bool trimmedAny = false;
        for (int i = 0; i < resolved.Count; i++)
        {
            bool isFinalNoSep = i == resolved.Count - 1 && !endedWithSep;
            if (isFinalNoSep)
                continue; // the final segment gets the stronger path-end trim below
            string seg = resolved[i];
            if (seg.Contains(':'))
                continue; // colon segments fail structural validation below; do not mangle the evidence
            if (seg.EndsWith('.') && !seg.EndsWith("..", StringComparison.Ordinal))
            {
                resolved[i] = seg[..^1];
                trimmedAny = true;
            }
        }
        if (!endedWithSep && resolved.Count > 0 && resolved[^1] != "..")
        {
            // The path-end trim is textual and runs before the stream suffix is split, exactly
            // as GetFullPathName does — "file:stream..." opens stream "stream", not "stream...".
            // A surviving ".." (only possible on unrooted paths) is a relative-parent marker,
            // not a name, and the documented rules exempt it from the trim.
            string last = resolved[^1];
            string trimmed = last.TrimEnd('.', ' ');
            if (trimmed.Length != last.Length)
                trimmedAny = true;
            if (trimmed.Length == 0)
            {
                // "C:\foo\..." -> Windows trims to "C:\foo\" and the separator survives.
                resolved.RemoveAt(resolved.Count - 1);
                endedWithSep = true;
            }
            else
            {
                resolved[^1] = trimmed;
            }
        }
        if (trimmedAny)
        {
            string after = Rebuild(root, resolved, endedWithSep, streamSuffix: null);
            transformations.Add(new PathTransformation(TransformationKind.TrailingDotsAndSpacesTrimmed, work, after));
            flags |= PathFlags.TrailingDotsOrSpacesStripped;
            work = after;
        }

        // ---- 7. alternate data stream suffix -------------------------------------------------
        // A colon is legal only in the final component of a path that does not end in a
        // separator (the drive colon was consumed by root parsing). Anywhere else it cannot be
        // part of a well-formed path and the input is rejected — never silently repaired.
        string? streamName = null;
        string? streamType = null;
        for (int i = 0; i < resolved.Count; i++)
        {
            string seg = resolved[i];
            int colon = seg.IndexOf(':');
            if (colon < 0)
                continue;

            bool isFinalNoSep = i == resolved.Count - 1 && !endedWithSep;
            if (!isFinalNoSep)
                return NormalizedPath.Failure(path,
                    $"colon in directory component '{seg}': an alternate data stream can only appear on the final component", transformations);

            string name = seg[..colon];
            string streamPart = seg[(colon + 1)..];
            int colon2 = streamPart.IndexOf(':');
            if (colon2 < 0)
            {
                streamName = streamPart;
            }
            else
            {
                streamName = streamPart[..colon2];
                streamType = streamPart[(colon2 + 1)..];
                if (streamType.Contains(':'))
                    return NormalizedPath.Failure(path,
                        $"too many colons in component '{seg}': expected name:stream or name:stream:$TYPE", transformations);
                if (streamType.Length == 0)
                    return NormalizedPath.Failure(path, $"empty stream type in component '{seg}'", transformations);
            }
            if (name.Length == 0)
                return NormalizedPath.Failure(path, $"stream suffix ':{streamPart}' on an empty component name", transformations);
            if (streamName.Length == 0 && streamType is null)
                return NormalizedPath.Failure(path, $"empty stream name in component '{seg}'", transformations);

            resolved[i] = name;
            flags |= PathFlags.AlternateDataStream;
            string after = Rebuild(root, resolved, endedWithSep, streamSuffix: null);
            transformations.Add(new PathTransformation(TransformationKind.AlternateDataStreamSplit, work, after));
            work = after;
        }

        // Canonical stream identity: type defaults to $DATA so "f:s" and "f:s:$DATA" agree, and
        // "::$DATA" (the default data stream) is the file itself — no distinct identity.
        string? canonicalStream = null;
        if (streamName is not null)
        {
            string typeLower = (streamType ?? PathLimits.DefaultStreamType).ToLowerInvariant();
            if (streamName.Length == 0 && typeLower == "$data")
                flags |= PathFlags.DefaultDataStream;
            else
                canonicalStream = streamName.ToLowerInvariant() + ":" + typeLower;
        }

        // ---- 8. per-component validation and evidence flags ----------------------------------
        foreach (string seg in resolved)
        {
            if (CharacterSets.FirstIllegalNameChar(seg) is char bad)
                return NormalizedPath.Failure(path, IllegalCharMessage(bad, seg), transformations);
            if (CharacterSets.IsReservedDeviceName(seg))
                flags |= PathFlags.ReservedDeviceName;
            if (CharacterSets.LooksLikeShortName(seg))
                flags |= PathFlags.ShortNameComponent;
            if (CharacterSets.ContainsHomoglyphs(seg))
                flags |= PathFlags.HomoglyphCharacters;
        }
        foreach (string? streamPart in new[] { streamName, streamType })
        {
            if (streamPart is null)
                continue;
            if (CharacterSets.FirstIllegalNameChar(streamPart) is char bad)
                return NormalizedPath.Failure(path, IllegalCharMessage(bad, streamPart), transformations);
            if (CharacterSets.ContainsHomoglyphs(streamPart))
                flags |= PathFlags.HomoglyphCharacters;
        }

        // ---- 9. trailing separator -----------------------------------------------------------
        // Dropped from the result — except when the final segment ends in a dot or space, where
        // the separator is load-bearing (it is what protects the name from the path-end trim,
        // so removing it would change which object the path names on re-parse).
        bool keepSep = endedWithSep && resolved.Count > 0 &&
                       (resolved[^1].EndsWith('.') || resolved[^1].EndsWith(' '));
        if (endedWithSep && !keepSep)
        {
            string after = Rebuild(root, resolved, endedWithSep: false, streamSuffix: null);
            if (!string.Equals(after, work, StringComparison.Ordinal))
                transformations.Add(new PathTransformation(TransformationKind.TrailingSeparatorRemoved, work, after));
            work = after;
        }

        // ---- 10. assemble display and canonical forms ----------------------------------------
        string? streamSuffix = streamName is null
            ? null
            : ":" + streamName + (streamType is null ? "" : ":" + streamType);
        string display = Rebuild(root, resolved, keepSep, streamSuffix);

        var canonicalSegments = new string[resolved.Count];
        for (int i = 0; i < resolved.Count; i++)
            canonicalSegments[i] = resolved[i].ToLowerInvariant();
        string canonical = RebuildCanonical(root, canonicalSegments);

        if (!string.Equals(display, display.ToLowerInvariant(), StringComparison.Ordinal))
        {
            string canonicalFull = canonicalStream is null ? canonical : canonical + ":" + canonicalStream;
            transformations.Add(new PathTransformation(TransformationKind.CaseFolded, display, canonicalFull));
        }

        return new NormalizedPath(
            OperationState.Ok,
            path,
            failureReason: null,
            root.Kind,
            root.Space,
            flags,
            display,
            canonical,
            root.CanonicalRoot,
            canonicalSegments,
            streamName,
            streamType,
            canonicalStream,
            transformations);
    }

    // -------------------------------------------------------------------- root / prefix parsing

    /// <summary>Mutable root-parse scratch: what the path is rooted on and what text remains.</summary>
    private sealed class RootParse
    {
        public PathKind Kind;
        public PathRootSpace Space;
        public string CanonicalRoot = "";
        public string DisplayRoot = "";
        public string Rest = "";
        public int ConsumeCount;       // leading segments the root still owns (UNC: 2, device: 1)
        public bool IsUnc;             // whether the consumed segments are server + share
        public bool PrefixRewritten;   // a \\?\-family prefix was rewritten to comparison form
    }

    private static bool TryParseRoot(string s, out RootParse root, out string? error)
    {
        root = new RootParse();
        error = null;

        if (s.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // \\?\ and \\.\ device-namespace prefixes (and their //?/-style spellings, already
            // separator-normalised by the time we get here).
            if (s.Length >= 3 && s[2] is '?' or '.' && (s.Length == 3 || s[3] == '\\'))
            {
                char prefixChar = s[2];
                string rest0 = s.Length <= 4 ? "" : s[4..];

                if (rest0.Equals("UNC", StringComparison.OrdinalIgnoreCase) ||
                    rest0.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    root.Kind = PathKind.ExtendedUnc;
                    root.Space = PathRootSpace.Unc;
                    root.Rest = rest0.Length <= 4 ? "" : rest0[4..];
                    root.ConsumeCount = 2;
                    root.IsUnc = true;
                    root.PrefixRewritten = true; // \\?\UNC\srv\share -> \\srv\share
                    return true;
                }

                if (rest0.Equals("GLOBALROOT", StringComparison.OrdinalIgnoreCase) ||
                    rest0.StartsWith(@"GLOBALROOT\", StringComparison.OrdinalIgnoreCase))
                {
                    root.Kind = PathKind.GlobalRoot;
                    root.Space = PathRootSpace.GlobalRoot;
                    root.DisplayRoot = @"\\.\" + rest0[..10];
                    root.CanonicalRoot = @"\\.\globalroot";
                    root.Rest = rest0.Length <= 11 ? "" : rest0[11..];
                    root.PrefixRewritten = prefixChar == '?';
                    return true;
                }

                if (rest0.Length >= 2 && char.IsAsciiLetter(rest0[0]) && rest0[1] == ':' &&
                    (rest0.Length == 2 || rest0[2] == '\\'))
                {
                    // \\?\C:\x and \\.\C:\x are the drive volume: same comparison space as C:\x.
                    root.Kind = prefixChar == '?' ? PathKind.Extended : PathKind.Device;
                    root.Space = PathRootSpace.Drive;
                    root.DisplayRoot = rest0[0] + @":\";
                    root.CanonicalRoot = char.ToLowerInvariant(rest0[0]) + @":\";
                    root.Rest = rest0.Length <= 3 ? "" : rest0[3..];
                    root.PrefixRewritten = true; // \\?\C:\x -> C:\x
                    return true;
                }

                if (rest0.Length == 0)
                {
                    error = $@"device namespace path '{s}' is missing a device name";
                    return false;
                }

                root.Kind = prefixChar == '?' ? PathKind.Extended : PathKind.Device;
                root.Space = PathRootSpace.Device;
                root.Rest = rest0;
                root.ConsumeCount = 1;
                root.PrefixRewritten = prefixChar == '?'; // canonical device root uses \\.\
                return true;
            }

            // Plain UNC.
            root.Kind = PathKind.Unc;
            root.Space = PathRootSpace.Unc;
            root.Rest = s[2..];
            root.ConsumeCount = 2;
            root.IsUnc = true;
            if (root.Rest.Length == 0)
            {
                error = "UNC path is missing a server name";
                return false;
            }
            return true;
        }

        if (s.Length >= 2 && s[1] == ':')
        {
            if (!char.IsAsciiLetter(s[0]))
            {
                // "1:\x" is not a drive and not a stream on a sensible file. A colon this early
                // in a relative path is only accepted as an ADS on a single-component name,
                // which the segment pipeline handles; a path-like remainder is malformed.
                if (s.Length >= 3 && s[2] == '\\')
                {
                    error = $"invalid drive letter '{s[0]}': drives are A-Z";
                    return false;
                }
            }
            else if (s.Length >= 3 && s[2] == '\\')
            {
                root.Kind = PathKind.DriveAbsolute;
                root.Space = PathRootSpace.Drive;
                root.DisplayRoot = s[0] + @":\";
                root.CanonicalRoot = char.ToLowerInvariant(s[0]) + @":\";
                root.Rest = s[3..];
                return true;
            }
            else
            {
                // Drive-relative: C:foo resolves against C:'s current directory, which pure
                // string logic cannot know. Normalised, but containment reports Incomplete.
                root.Kind = PathKind.DriveRelative;
                root.Space = PathRootSpace.DriveCurrentDirectory;
                root.DisplayRoot = s[0] + ":";
                root.CanonicalRoot = char.ToLowerInvariant(s[0]) + ":";
                root.Rest = s[2..];
                return true;
            }
        }

        if (s[0] == '\\')
        {
            root.Kind = PathKind.RootRelative;
            root.Space = PathRootSpace.CurrentDrive;
            root.DisplayRoot = @"\";
            root.CanonicalRoot = @"\";
            root.Rest = s[1..];
            return true;
        }

        root.Kind = PathKind.Relative;
        root.Space = PathRootSpace.Relative;
        root.Rest = s;
        return true;
    }

    // ------------------------------------------------------------------------------- assembly

    /// <summary>
    /// Rebuild a display-form path from a root and segments. A relative path whose segments all
    /// resolved away renders as "." — an empty string would fail re-normalisation, and "." is
    /// the honest spelling of "the (unknown) current directory".
    /// </summary>
    private static string Rebuild(RootParse root, IReadOnlyList<string> segments, bool endedWithSep, string? streamSuffix)
    {
        var sb = new StringBuilder();
        sb.Append(root.DisplayRoot);
        for (int i = 0; i < segments.Count; i++)
        {
            if (sb.Length > 0 && sb[^1] != '\\' && root.Kind != PathKind.DriveRelative)
                sb.Append('\\');
            else if (i > 0)
                sb.Append('\\');
            sb.Append(segments[i]);
        }
        // A trailing separator is kept through the stage snapshots so its eventual removal can
        // be audited. It is meaningful after a segment, and after a structural root that has no
        // separator of its own (a bare \\server\share or \\.\device) — but never invented for a
        // bare drive-relative "C:", where it would turn the path into a drive-absolute one.
        if (endedWithSep && sb.Length > 0 && sb[^1] != '\\' &&
            (segments.Count > 0 ||
             root.Space is PathRootSpace.Unc or PathRootSpace.Device or PathRootSpace.GlobalRoot))
        {
            sb.Append('\\');
        }
        if (streamSuffix is not null)
            sb.Append(streamSuffix);
        if (sb.Length == 0)
            return ".";
        return sb.ToString();
    }

    /// <summary>
    /// The whole path with only the <c>\\?\</c>-family prefix rewritten to comparison form and
    /// everything after it untouched — the After snapshot for <see cref="TransformationKind.PrefixNormalized"/>.
    /// </summary>
    private static string PrefixNormalizedForm(RootParse root) => root.Space switch
    {
        PathRootSpace.Drive => root.DisplayRoot + root.Rest,
        PathRootSpace.Unc => @"\\" + root.Rest,
        PathRootSpace.Device => @"\\.\" + root.Rest,
        PathRootSpace.GlobalRoot => root.Rest.Length == 0 ? root.DisplayRoot : root.DisplayRoot + @"\" + root.Rest,
        _ => root.DisplayRoot + root.Rest,
    };

    /// <summary>Canonical form: canonical root + lower-cased segments, never a trailing separator.</summary>
    private static string RebuildCanonical(RootParse root, IReadOnlyList<string> canonicalSegments)
    {
        var sb = new StringBuilder();
        sb.Append(root.CanonicalRoot);
        for (int i = 0; i < canonicalSegments.Count; i++)
        {
            if (sb.Length > 0 && sb[^1] != '\\' && root.Kind != PathKind.DriveRelative)
                sb.Append('\\');
            else if (i > 0)
                sb.Append('\\');
            sb.Append(canonicalSegments[i]);
        }
        if (sb.Length == 0)
            return ".";
        return sb.ToString();
    }

    private static bool ValidateRootComponent(string component, string what, out string? error)
    {
        if (CharacterSets.FirstIllegalNameChar(component) is char bad)
        {
            error = $"{IllegalCharMessage(bad, component)} ({what})";
            return false;
        }
        if (component.Contains(':'))
        {
            error = $"colon in {what} '{component}'";
            return false;
        }
        error = null;
        return true;
    }

    private static string IllegalCharMessage(char bad, string component)
    {
        string shown = bad >= 0x20 ? $"'{bad}' (U+{(int)bad:X4})" : $"U+{(int)bad:X4}";
        return $"illegal character {shown} in component '{component}'";
    }

    // -------------------------------------------------------------------- environment expansion

    /// <summary>
    /// Expand <c>%VAR%</c> references from the caller-supplied dictionary. Lookup is
    /// case-insensitive (Windows environment semantics). Text between two '%' signs that is not
    /// a plausible variable name is left literal, mirroring ExpandEnvironmentStrings' leniency
    /// for stray '%'; a plausible name that is NOT in the dictionary fails the operation —
    /// passing "%SystemRoot%" through as literal text would hand the guard a string that is not
    /// the path the operation will actually touch. Expansion is single-pass: a value containing
    /// '%' is inserted literally, never re-expanded, so a hostile dictionary cannot loop.
    /// </summary>
    private static bool TryExpandEnvironment(
        string input,
        IReadOnlyDictionary<string, string>? environment,
        List<PathTransformation> transformations,
        out string result,
        out string? error)
    {
        error = null;
        if (!input.Contains('%'))
        {
            result = input;
            return true;
        }

        var sb = new StringBuilder(input.Length);
        int i = 0;
        while (i < input.Length)
        {
            char c = input[i];
            if (c != '%')
            {
                sb.Append(c);
                i++;
                continue;
            }
            int close = input.IndexOf('%', i + 1);
            if (close < 0)
            {
                sb.Append(input, i, input.Length - i); // lone '%': literal to the end
                break;
            }
            string name = input[(i + 1)..close];
            if (!CharacterSets.IsPlausibleEnvName(name))
            {
                // Not a variable reference; this '%' is literal. The closing '%' may still open
                // a real reference, so rescan from the next character.
                sb.Append('%');
                i++;
                continue;
            }
            if (!TryLookup(environment, name, out string value))
            {
                result = input;
                error = $"unresolved environment variable '%{name}%': not present in the supplied environment";
                return false;
            }
            sb.Append(value);
            transformations.Add(new PathTransformation(TransformationKind.EnvironmentVariableExpanded, $"%{name}%", value));
            i = close + 1;
        }
        result = sb.ToString();
        return true;
    }

    private static bool TryLookup(IReadOnlyDictionary<string, string>? environment, string name, out string value)
    {
        value = "";
        if (environment is null)
            return false;
        if (environment.TryGetValue(name, out string? direct))
        {
            value = direct;
            return true;
        }
        // The dictionary may use a case-sensitive comparer; Windows variable names are not.
        // Scan and, if several keys differ only by case, pick the ordinally-smallest key so the
        // answer never depends on dictionary enumeration order.
        string? bestKey = null;
        foreach (string key in environment.Keys)
        {
            if (!key.Equals(name, StringComparison.OrdinalIgnoreCase))
                continue;
            if (bestKey is null || string.CompareOrdinal(key, bestKey) < 0)
                bestKey = key;
        }
        if (bestKey is null)
            return false;
        value = environment[bestKey];
        return true;
    }
}
