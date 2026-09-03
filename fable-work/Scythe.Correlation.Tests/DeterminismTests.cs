using System.Globalization;
using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>Same findings, same output — in any arrival order, twice in a row, under a hostile culture.</summary>
public sealed class DeterminismTests
{
    private static List<FindingReference> MixedRun()
    {
        var findings = new List<FindingReference>
        {
            Finding("F01", @"launched C:\Users\x\AppData\evil.exe from HKLM\Software\Microsoft\Windows\CurrentVersion\Run\\Updater"),
            Finding("F02", @"task runs c:\users\X\appdata\EVIL.EXE nightly", EntityReference.RegistryPath(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\\updater")),
            Finding("F03", "socket to 203.0.113.9:443 owned by PID 4412"),
            Finding("F04", "handle", EntityReference.ProcessId(4412)),
            Finding("F05", "beacon to c2.evil.example", EntityReference.NetworkPeer("203.0.113.9")),
            Finding("F06", @"lone C:\lonely.exe"),
            Finding("F07", @"\\srv\share\tool.exe copied", EntityReference.Path(@"\\?\UNC\SRV\Share\tool.exe")),
            Finding("F08", "", EntityReference.Path(@"relative")),
            Finding("F09", @"C:\a\b\..\c.exe", anchor: RunTime.AddSeconds(-30)),
            Finding("F10", @"C:\a\c.exe"),
        };

        // A common noun on top of all of it.
        for (var i = 0; i < ChainBuilder.CommonNounThreshold + 3; i++)
        {
            findings.Add(Finding($"N{i:D2}", @"via C:\Windows\System32\cmd.exe"));
        }

        return findings;
    }

    [Fact]
    public void TheSameRunTwiceRendersByteIdentically()
    {
        var first = CanonicalWriter.Write(Build(MixedRun()));
        var second = CanonicalWriter.Write(Build(MixedRun()));
        Assert.Equal(first, second);
    }

    [Fact]
    public void EveryPermutationOfArrivalOrderRendersByteIdentically()
    {
        var baseline = MixedRun();
        var expected = CanonicalWriter.Write(Build(baseline));

        foreach (var seed in new[] { 1, 7, 42, 1234, 99999, 31337 })
        {
            var shuffled = Shuffled(baseline, seed);
            Assert.NotEqual(baseline.Select(f => f.Id), shuffled.Select(f => f.Id)); // the shuffle did something
            Assert.Equal(expected, CanonicalWriter.Write(Build(shuffled)));
        }
    }

    [Fact]
    public void ReversedArrivalOrderNominatesTheSameFirstFindings()
    {
        var baseline = MixedRun();
        var reversed = baseline.AsEnumerable().Reverse().ToList();
        var a = Build(baseline).Chains.Select(c => c.FirstFindingId).ToArray();
        var b = Build(reversed).Chains.Select(c => c.FirstFindingId).ToArray();
        Assert.Equal(a, b);
    }

    [Fact]
    public void TheRenderingHasTheExpectedShape()
    {
        var text = CanonicalWriter.Write(Build(MixedRun()));

        // Pinned in full so any change to ordering, spelling or classification is visible in a diff.
        var expected =
            "chains=3\n" +
            @"chain first=F01 members=F01|F02 joins=Path:C:\Users\x\AppData\evil.exe|RegistryPath:HKLM\Software\Microsoft\Windows\CurrentVersion\Run\\Updater" + "\n" +
            "chain first=F03 members=F03|F04|F05 joins=ProcessId:4412|NetworkPeer:203.0.113.9\n" +
            @"chain first=F09 members=F09|F10 joins=Path:C:\a\c.exe" + "\n" +
            "unchained=F06|F07|F08|N00|N01|N02|N03|N04|N05|N06|N07|N08|N09|N10|N11|N12\n" +
            // Path order is ordinal-ignore-case: 'a' and 'l' fold above 'U' and 'W'; '\' (0x5C) sorts after 'C'.
            @"census Path:C:\a\c.exe class=Shared refs=F09|F10" + "\n" +
            @"census Path:C:\lonely.exe class=Single refs=F06" + "\n" +
            @"census Path:C:\Users\x\AppData\evil.exe class=Shared refs=F01|F02" + "\n" +
            @"census Path:C:\Windows\System32\cmd.exe class=CommonNoun refs=N00|N01|N02|N03|N04|N05|N06|N07|N08|N09|N10|N11|N12" + "\n" +
            @"census Path:\\SRV\Share\tool.exe class=Single refs=F07" + "\n" + // ordinal-smallest of the two spellings seen
            @"census RegistryPath:HKLM\Software\Microsoft\Windows\CurrentVersion\Run\\Updater class=Shared refs=F01|F02" + "\n" +
            "census ProcessId:4412 class=Shared refs=F03|F04\n" +
            "census HostName:c2.evil.example class=Single refs=F05\n" +
            "census NetworkPeer:203.0.113.9 class=Shared refs=F03|F05\n" +
            "rejected F08 Path 'relative' not an absolute drive-letter or UNC path\n";

        Assert.Equal(expected, text);
    }

    [Fact]
    public void AHostileCurrentCultureDoesNotChangeTheRendering()
    {
        // InvariantGlobalization is on package-wide, so a named culture is inert here (see the
        // Q1 handoff). A clone of the invariant culture with its number format mutated is not:
        // any un-invariant integer formatting in the output would pick up the strange digits.
        var hostile = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        hostile.NumberFormat.NegativeSign = "~";
        hostile.NumberFormat.NumberGroupSeparator = "'";
        hostile.NumberFormat.NumberDecimalSeparator = ",";

        var expected = CanonicalWriter.Write(Build(MixedRun()));
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = hostile;
            Assert.Equal(expected, CanonicalWriter.Write(Build(MixedRun())));
            Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseProcessId(-5).State);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void EntityEqualityAndOrderingAgree()
    {
        var a = Unwrap(EntityNormaliser.NormalisePath(@"C:\Tools\run.exe"));
        var b = Unwrap(EntityNormaliser.NormalisePath(@"c:\tools\RUN.EXE"));
        var c = Unwrap(EntityNormaliser.NormalisePath(@"C:\Tools\run2.exe"));

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.NotEqual(a, c);
        Assert.Equal(0, Entity.Ordering.Compare(a, a));
        Assert.NotEqual(0, Entity.Ordering.Compare(a, b)); // same entity, different spelling: still totally ordered
        Assert.True(Entity.Ordering.Compare(a, c) < 0);

        var pid = Unwrap(EntityNormaliser.NormaliseProcessId(1));
        Assert.True(Entity.Ordering.Compare(c, pid) < 0); // kind order first
    }
}
