namespace Scythe.Intel.Tests;

using Scythe.Intel;

internal static class TestData
{
    public const string Sha256A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public const string Sha256B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public const string Sha1A = "cccccccccccccccccccccccccccccccccccccccc";
    public const string Md5A = "dddddddddddddddddddddddddddddddd";

    public static FeedSource Feed(FeedFormat format, string content, string id = "f1", string name = "Feed One")
        => new(id, name, format, content);

    public static IngestResult Ingest(params FeedSource[] feeds)
        => FeedNormalizer.Ingest(feeds);

    public static IngestResult Ingest(IngestBudget budget, params FeedSource[] feeds)
        => FeedNormalizer.Ingest(feeds, budget);

    /// <summary>Single plain-text feed, one value per line.</summary>
    public static IngestResult IngestLines(params string[] lines)
        => Ingest(Feed(FeedFormat.PlainText, string.Join('\n', lines)));
}
