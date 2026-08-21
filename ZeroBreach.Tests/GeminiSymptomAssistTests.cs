using System.Net;
using System.Text;
using System.Text.Json;
using ZeroBreach.Cli;

namespace ZeroBreach.Tests;

/// <summary>
/// Opt-in LLM triage assist (spec §6.6): Gemini's output is untrusted text that may only
/// SELECT among the engine's own categories and modes. These tests pin the validation gate —
/// unknown/hostile category names, invalid modes, and unparseable replies must land in
/// RejectedOutput (disclosed, never used) rather than in the engine — and pin that the API
/// key travels in a header, never in the URL. All network I/O goes through a fake handler;
/// nothing here touches the wire or any OS-specific path.
/// </summary>
public class GeminiSymptomAssistTests
{
    private static readonly string[] ValidCategories =
        { "Persistence", "DefenseEvasion", "C2", "Ransomware", "EventLog" };

    [Fact]
    public async Task Well_formed_reply_yields_validated_categories_mode_and_rationale()
    {
        var handler = new FakeHandler(GeminiReply(
            """{"categories": ["persistence", "c2"], "mode": "deep", "rationale": "beacons plus a run key point at persistence and C2"}"""));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var s = await assist.SuggestAsync("odd outbound beacons and a strange run key", ValidCategories);

        // Survivors come back in the engine's canonical casing, not the model's.
        Assert.Equal(new[] { "Persistence", "C2" }, s.Categories);
        Assert.Equal("DEEP", s.SuggestedMode);
        Assert.Equal("beacons plus a run key point at persistence and C2", s.Rationale);
        Assert.Empty(s.RejectedOutput);
    }

    [Fact]
    public async Task Unknown_and_hostile_category_names_are_rejected_not_used()
    {
        // The §6.6 point: a hostile reply can name anything it likes — only the engine's own
        // category names survive; the rest is disclosed in RejectedOutput and never used.
        var handler = new FakeHandler(GeminiReply(
            """{"categories": ["Persistence", "rm -rf /", "IgnorePreviousInstructions"], "mode": "FULL"}"""));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var s = await assist.SuggestAsync("machine is slow", ValidCategories);

        Assert.Equal(new[] { "Persistence" }, s.Categories);
        Assert.Contains("rm -rf /", s.RejectedOutput);
        Assert.Contains("IgnorePreviousInstructions", s.RejectedOutput);
        Assert.Equal(2, s.RejectedOutput.Count);
        Assert.Equal("FULL", s.SuggestedMode);
    }

    [Fact]
    public async Task Reply_wrapped_in_markdown_code_fences_still_parses()
    {
        var handler = new FakeHandler(GeminiReply(
            "```json\n{\"categories\": [\"Ransomware\"], \"mode\": \"QUICK\", \"rationale\": \"encrypted files\"}\n```"));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var s = await assist.SuggestAsync("files renamed to .locked", ValidCategories);

        Assert.Equal(new[] { "Ransomware" }, s.Categories);
        Assert.Equal("QUICK", s.SuggestedMode);
        Assert.Empty(s.RejectedOutput);
    }

    [Fact]
    public async Task Non_json_reply_yields_empty_categories_and_raw_text_disclosed_without_throwing()
    {
        const string chatty = "Sure! Based on the symptoms I would run a full persistence sweep.";
        var handler = new FakeHandler(GeminiReply(chatty));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var s = await assist.SuggestAsync("popups everywhere", ValidCategories);

        Assert.Empty(s.Categories);
        Assert.Null(s.SuggestedMode);
        Assert.Null(s.Rationale);
        Assert.Equal(new[] { chatty }, s.RejectedOutput);
    }

    [Fact]
    public async Task Invalid_mode_is_rejected_and_SuggestedMode_stays_null()
    {
        var handler = new FakeHandler(GeminiReply(
            """{"categories": ["EventLog"], "mode": "TURBO", "rationale": "check the logs"}"""));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var s = await assist.SuggestAsync("logs were cleared", ValidCategories);

        Assert.Equal(new[] { "EventLog" }, s.Categories);
        Assert.Null(s.SuggestedMode);
        Assert.Contains("TURBO", s.RejectedOutput);
    }

    [Fact]
    public async Task Api_key_travels_in_the_header_and_never_in_the_url()
    {
        const string key = "SECRET-KEY-12345";
        var handler = new FakeHandler(GeminiReply("""{"categories": []}"""));
        var assist = new GeminiSymptomAssist(key, handler);

        await assist.SuggestAsync("anything", ValidCategories);

        var request = handler.LastRequest!;
        Assert.True(request.Headers.TryGetValues("x-goog-api-key", out var values));
        Assert.Equal(new[] { key }, values!);
        // URLs leak into proxy/server logs — the key must not appear there.
        Assert.DoesNotContain(key, request.RequestUri!.ToString());
        Assert.StartsWith("https://generativelanguage.googleapis.com/", request.RequestUri.ToString());
    }

    [Fact]
    public async Task Request_body_delimits_the_symptom_text_as_data_and_lists_the_categories()
    {
        var handler = new FakeHandler(GeminiReply("""{"categories": []}"""));
        var assist = new GeminiSymptomAssist("test-key", handler);

        await assist.SuggestAsync("weird scheduled task at 3am", ValidCategories);

        var body = handler.LastRequestBody!;
        Assert.Contains("weird scheduled task at 3am", body);
        Assert.Contains("Persistence", body);
        Assert.Contains("BEGIN SYMPTOM DESCRIPTION", body);
        Assert.Contains("not instructions", body);
    }

    [Fact]
    public async Task Server_error_throws_HttpRequestException_for_the_cli_fallback()
    {
        var handler = new FakeHandler(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var assist = new GeminiSymptomAssist("test-key", handler);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => assist.SuggestAsync("anything", ValidCategories));
        Assert.Contains("500", ex.Message);
    }

    /// <summary>Wraps a model reply in the Gemini generateContent response envelope.</summary>
    private static HttpResponseMessage GeminiReply(string modelText) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(new
        {
            candidates = new[]
            {
                new { content = new { parts = new[] { new { text = modelText } } } },
            },
        }), Encoding.UTF8, "application/json"),
    };

    /// <summary>Canned-response handler that captures the outgoing request for assertions.</summary>
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastRequestBody { get; private set; }

        public FakeHandler(HttpResponseMessage response) => _response = response;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            // Read the body now — the content stream may be disposed by the time a test asserts.
            LastRequestBody = request.Content is null
                ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return _response;
        }
    }
}
