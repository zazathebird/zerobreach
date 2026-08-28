using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// The adversarial suite: every known spelling trick for walking a path past a guard on a
/// protected directory. Each attack must land as IsInside=true (refused because it IS inside)
/// or as Incomplete (refused because it cannot be proven) — an attack that comes back
/// Ok/Outside has found a bypass, and that is the worst bug this library can ship.
/// </summary>
public sealed class GuardBypassTests
{
    private const string Protected = @"C:\Windows";

    /// <summary>Spellings of locations inside (or equal to) C:\Windows. All must be caught as Inside/Equal.</summary>
    public static TheoryData<string> InsideSpellings() => new()
    {
        // The shipped bug this library exists to kill: forward slashes.
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows",
        // Mixed and duplicated separators.
        @"C:/Windows\System32",
        @"C:\\Windows\\\System32",
        // Case tricks.
        @"C:\WINDOWS\SYSTEM32",
        @"c:\windows\system32",
        // Dot and dot-dot laundering.
        @"C:\Windows\.\System32",
        @"C:\Windows\System32\..\System32",
        @"C:\Users\..\Windows\System32",
        @"C:\.\Windows",
        @"C:\..\Windows",                       // '..' clamped at the root still lands in C:\Windows
        @"C:\Windows\System32\..\..\Windows",   // resolves back to the directory itself
        // Trailing dots and spaces (Windows strips them silently).
        @"C:\Windows.",
        @"C:\Windows ",
        @"C:\Windows...",
        @"C:\Windows. . .",
        @"C:\Windows\System32.",
        // Trailing separator.
        @"C:\Windows\",
        // NT namespace prefixes reaching the same volume.
        @"\\?\C:\Windows\System32",
        @"\\.\C:\Windows\System32",
        "//?/C:/Windows/System32",
        "//./C:/Windows",
        @"\\?\C:\Windows\..\Windows\System32",
        // Alternate data streams on and under the protected directory.
        @"C:\Windows::$DATA",
        @"C:\Windows:payload",
        @"C:\Windows\System32\kernel32.dll:evil",
        @"C:\Windows\System32:$I30:$INDEX_ALLOCATION",
        // Combinations.
        "C:/WINDOWS/./System32/../SYSTEM32/",
        @"\\?\C:\WINDOWS.",
    };

    /// <summary>
    /// Spellings that may reach C:\Windows but cannot be proven to from strings alone.
    /// All must come back Incomplete — refused, but honestly, never as a false "Outside".
    /// </summary>
    public static TheoryData<string> UndecidableSpellings() => new()
    {
        @"\\localhost\C$\Windows\System32",
        @"\\127.0.0.1\c$\Windows",
        @"\\localhost\ADMIN$",                          // ADMIN$ is C:\Windows itself
        @"\\ws-042\C$\Windows\System32",                // admin share on any server may be this machine
        @"\\?\GLOBALROOT\Device\HarddiskVolume2\Windows\System32",
        @"\\.\GLOBALROOT\Device\HarddiskVolume2\Windows",
        @"\\.\HarddiskVolume2\Windows",
        @"Windows\System32",                            // relative: depends on the current directory
        @"\Windows\System32",                           // rooted on the unknown current drive
        @"C:Windows\System32",                          // drive-relative: unknown current directory on C:
        @"..\..\Windows\System32",
    };

    [Theory]
    [MemberData(nameof(InsideSpellings))]
    public void AttackSpelling_IsCaughtInside(string attack)
    {
        ContainmentResult r = PathContainment.IsInside(attack, Protected);
        Assert.Equal(OperationState.Ok, r.State);
        Assert.True(r.IsInside, $"BYPASS: '{attack}' was not recognised as inside {Protected}");
    }

    [Theory]
    [MemberData(nameof(UndecidableSpellings))]
    public void UnprovableSpelling_IsRefusedAsIncomplete(string attack)
    {
        ContainmentResult r = PathContainment.IsInside(attack, Protected);
        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.False(r.IsInside);
        Assert.NotNull(r.Reason);
    }

    [Theory]
    [MemberData(nameof(InsideSpellings))]
    [MemberData(nameof(UndecidableSpellings))]
    public void NoAttackSpelling_EverComesBackOutside(string attack)
    {
        // The single most important assertion in the suite, stated as its own property:
        // nothing in the attack corpus may produce Ok/Outside against the protected directory.
        ContainmentResult r = PathContainment.IsInside(attack, Protected);
        Assert.False(r.State == OperationState.Ok && r.Verdict == ContainmentVerdict.Outside,
            $"BYPASS: '{attack}' came back Ok/Outside against {Protected}");
    }

    // ------------------------------------------------------------------ flagged-but-outside evidence

    [Fact]
    public void ShortNameSpelling_IsOutsideButCarriesTheFlag()
    {
        // "C:\PROGRA~1" may alias "C:\Program Files" but resolving needs the file system.
        // The contract: the verdict is honest (textually outside) and the flag is the guard's
        // cue that the answer is not the whole story.
        NormalizedPath candidate = PathNormalizer.Normalize(@"C:\PROGRA~1\sub");
        ContainmentResult r = PathContainment.IsInside(candidate, PathNormalizer.Normalize(@"C:\Program Files"));
        Assert.Equal(ContainmentVerdict.Outside, r.Verdict);
        Assert.True(candidate.Flags.HasFlag(PathFlags.ShortNameComponent),
            "short-name evidence flag missing — the guard would have nothing to escalate on");
    }

    [Fact]
    public void HomoglyphSpelling_IsOutsideButCarriesTheFlag()
    {
        // Cyrillic о: really a DIFFERENT directory (that is the attack — evading a match),
        // so Outside is correct, and the homoglyph flag is the detection signal.
        NormalizedPath candidate = PathNormalizer.Normalize("C:\\Wind\u043Ews\\payload.exe");
        ContainmentResult r = PathContainment.IsInside(candidate, PathNormalizer.Normalize(Protected));
        Assert.Equal(ContainmentVerdict.Outside, r.Verdict);
        Assert.True(candidate.Flags.HasFlag(PathFlags.HomoglyphCharacters),
            "homoglyph evidence flag missing — the spoof would be invisible to the guard");
    }

    [Fact]
    public void EnvironmentSpelling_ResolvesAndIsCaught()
    {
        var env = new Dictionary<string, string> { ["WINDIR"] = @"C:\Windows" };
        Assert.True(PathContainment.IsInside(@"%WINDIR%\System32\config", Protected, env).IsInside);
    }

    [Fact]
    public void LegitimateOutsidePath_IsStillPermitted()
    {
        // Fail-closed must not mean fail-always: the guard has to let real work through.
        ContainmentResult r = PathContainment.IsInside(@"C:\Users\tech\report.txt", Protected);
        Assert.Equal(OperationState.Ok, r.State);
        Assert.Equal(ContainmentVerdict.Outside, r.Verdict);
        Assert.False(r.IsInside);
    }
}
