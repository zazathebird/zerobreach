namespace Scythe.Rules.Linting;

/// <summary>
/// Deliberately unrelated strings used to detect universal allowlists (BLUEPRINT §9).
/// An allowlist entry is supposed to describe one narrow, known-good thing; an entry that
/// matches <em>every one</em> of these — a path, a domain, a hash, prose, a registry key,
/// a URL, an address, an identifier — describes nothing and suppresses everything.
/// The set is public and explicit so a reader can judge its variety, and it only ever
/// grows: removing a canary weakens the check for every existing rule file.
/// </summary>
public static class AllowlistCanaries
{
    public static IReadOnlyList<string> All { get; } = new[]
    {
        // A Windows program path.
        @"C:\Program Files (x86)\Contoso Widgets\bin\widgetsvc.exe",
        // A DNS name.
        "telemetry.update.fabrikam-cdn.example",
        // A SHA-256 style hex hash.
        "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855c",
        // A sentence of prose.
        "The quick brown fox jumps over the lazy dog.",
        // A registry key.
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        // A URL with a query string.
        "https://cdn.example.net/assets/app.js?v=20240117",
        // A dotted-quad IPv4 address.
        "192.0.2.117",
        // A GUID.
        "7f9c2ba4-e88f-4be0-a1f3-0242ac120002",
    };
}
