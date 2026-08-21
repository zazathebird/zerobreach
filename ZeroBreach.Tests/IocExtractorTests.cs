using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Tests;

/// <summary>
/// IocExtractor is spec §6.6 territory: extraction from untrusted text is detection-staging
/// only — low-precision candidates that each need individual operator confirmation before
/// going live. These tests pin the classification, refanging, cautions, and dedup rules.
/// Pure string logic, OS-independent, so plain [Fact]/[Theory].
/// </summary>
public class IocExtractorTests
{
    [Fact]
    public void Refanged_domain_is_extracted_and_source_line_keeps_original()
    {
        var iocs = IocExtractor.Extract("beacons to evil-updates[.]example[.]com daily");

        var d = Assert.Single(iocs);
        Assert.Equal(IocKind.Domain, d.Kind);
        Assert.Equal("evil-updates.example.com", d.Value);
        Assert.Equal("beacons to evil-updates[.]example[.]com daily", d.SourceLine);
    }

    [Fact]
    public void Hxxp_url_yields_host_domain()
    {
        var iocs = IocExtractor.Extract("payload from hxxp://cdn[.]bad-host[.]net/stage2");

        Assert.Contains(iocs, i => i.Kind == IocKind.Domain && i.Value == "cdn.bad-host.net");
    }

    [Theory]
    [InlineData("[dot]")]
    [InlineData("(.)")]
    [InlineData("{.}")]
    public void Alternate_defang_styles_are_refanged(string dot)
    {
        var iocs = IocExtractor.Extract($"see evil{dot}com for details");
        Assert.Contains(iocs, i => i.Kind == IocKind.Domain && i.Value == "evil.com");
    }

    [Fact]
    public void Sha256_is_extracted_and_lowercased()
    {
        var hash = new string('A', 32) + new string('b', 32);
        var iocs = IocExtractor.Extract($"dropped file hash {hash} observed");

        var h = Assert.Single(iocs, i => i.Kind == IocKind.Sha256);
        Assert.Equal(hash.ToLowerInvariant(), h.Value);
    }

    [Fact]
    public void Invalid_dotted_quad_is_not_an_ip()
    {
        var iocs = IocExtractor.Extract("connects to 999.1.1.1 on boot");
        Assert.DoesNotContain(iocs, i => i.Kind == IocKind.Ipv4);
    }

    [Fact]
    public void Private_ip_carries_reserved_caution()
    {
        var iocs = IocExtractor.Extract("lateral movement to 10.0.0.5");

        var ip = Assert.Single(iocs, i => i.Kind == IocKind.Ipv4);
        Assert.Equal("10.0.0.5", ip.Value);
        Assert.NotNull(ip.Caution);
        Assert.Contains("private/reserved", ip.Caution);
    }

    [Fact]
    public void V_prefixed_quad_carries_version_caution()
    {
        // §6.6's canonical false positive: version strings parse as valid IPs.
        var iocs = IocExtractor.Extract("Product v1.2.3.4 was affected");

        var ip = Assert.Single(iocs, i => i.Kind == IocKind.Ipv4);
        Assert.Equal("1.2.3.4", ip.Value);
        Assert.NotNull(ip.Caution);
        Assert.Contains("version number", ip.Caution);
    }

    [Fact]
    public void Line_mentioning_version_carries_version_caution()
    {
        var iocs = IocExtractor.Extract("agent version 7.5.0.1 is vulnerable");

        var ip = Assert.Single(iocs, i => i.Kind == IocKind.Ipv4);
        Assert.NotNull(ip.Caution);
        Assert.Contains("version number", ip.Caution);
    }

    [Fact]
    public void Public_ip_has_no_caution()
    {
        var iocs = IocExtractor.Extract("C2 at 203.0.113.7");

        var ip = Assert.Single(iocs, i => i.Kind == IocKind.Ipv4);
        Assert.Null(ip.Caution);
    }

    [Fact]
    public void Domains_and_filenames_split_on_extension_list()
    {
        var iocs = IocExtractor.Extract(@"evil.com dropper.exe C:\temp\payload.dll");

        Assert.Contains(iocs, i => i.Kind == IocKind.Domain && i.Value == "evil.com");
        Assert.Contains(iocs, i => i.Kind == IocKind.Filename && i.Value == "dropper.exe");
        // A path contributes just its final filename component.
        Assert.Contains(iocs, i => i.Kind == IocKind.Filename && i.Value == "payload.dll");
        Assert.DoesNotContain(iocs, i => i.Kind == IocKind.Domain && i.Value.EndsWith(".exe"));
        Assert.DoesNotContain(iocs, i => i.Kind == IocKind.Domain && i.Value.EndsWith(".dll"));
    }

    [Fact]
    public void Dedup_is_case_insensitive_across_lines_first_occurrence_wins()
    {
        var iocs = IocExtractor.Extract("first sighting: EVIL.COM\nsecond sighting: evil.com\n");

        var d = Assert.Single(iocs);
        Assert.Equal("evil.com", d.Value);
        Assert.Equal("first sighting: EVIL.COM", d.SourceLine);
    }

    [Fact]
    public void Comment_lines_are_ignored()
    {
        var iocs = IocExtractor.Extract("# 203.0.113.7 evil.com dropper.exe\n# all commented out");
        Assert.Empty(iocs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n  \n")]
    public void Empty_input_yields_empty_list(string text)
    {
        Assert.Empty(IocExtractor.Extract(text));
    }

    [Fact]
    public void Url_path_components_are_not_domains()
    {
        // "gate.php" parsed as a domain: a dead indicator that can never match anything at
        // scan time, costing the operator a confirmation prompt for nothing.
        var iocs = IocExtractor.Extract("beacon seen to http://evil-c2.com/panel/gate.php");

        var domains = iocs.Where(i => i.Kind == IocKind.Domain).Select(i => i.Value).ToList();
        Assert.Contains("evil-c2.com", domains);
        Assert.DoesNotContain("gate.php", domains);
        Assert.DoesNotContain(domains, d => d.EndsWith(".php"));
    }

    [Fact]
    public void Url_path_components_are_not_domains_without_a_scheme()
    {
        var domains = IocExtractor.Extract("evil-c2.com/panel/gate.php")
            .Where(i => i.Kind == IocKind.Domain).Select(i => i.Value).ToList();

        Assert.Equal(new[] { "evil-c2.com" }, domains);
    }

    [Fact]
    public void Defanged_url_still_yields_only_the_host()
    {
        var iocs = IocExtractor.Extract("hxxp://bad[.]example[.]net/a/index.html");

        var domains = iocs.Where(i => i.Kind == IocKind.Domain).Select(i => i.Value).ToList();
        Assert.Contains("bad.example.net", domains);
        Assert.DoesNotContain("index.html", domains);
    }

    [Fact]
    public void A_payload_name_in_a_url_path_is_still_extracted_as_a_filename()
    {
        // Masking the path must not cost us the genuinely useful indicator in it.
        var iocs = IocExtractor.Extract("dropper at http://evil-c2.com/dl/payload.exe");

        Assert.Contains(iocs, i => i.Kind == IocKind.Filename && i.Value == "payload.exe");
        Assert.Contains(iocs, i => i.Kind == IocKind.Domain && i.Value == "evil-c2.com");
    }

    [Fact]
    public void A_bare_page_name_is_not_armed_as_anything()
    {
        // Too generic to be an indicator: it would match on any web server.
        var iocs = IocExtractor.Extract("the request went to gate.php");
        Assert.DoesNotContain(iocs, i => i.Value == "gate.php");
    }
}
