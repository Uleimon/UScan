using System.Text;
using UScan.Core.Hashing;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class HashingReadStreamTests
{
    [Theory]
    [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    public async Task Matches_known_vectors(string input, string expected)
    {
        await using var s = new HashingReadStream(new MemoryStream(Encoding.ASCII.GetBytes(input)));
        Assert.Equal(expected, await s.CompleteAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Eicar_hash_matches_published_value()
    {
        await using var s = new HashingReadStream(new MemoryStream(TestFiles.Eicar));
        Assert.Equal(TestFiles.EicarSha256, await s.CompleteAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Partially_consumed_stream_still_hashes_everything()
    {
        var data = new byte[300_000];
        Random.Shared.NextBytes(data);
        await using var s = new HashingReadStream(new MemoryStream(data));
        var buf = new byte[1000];
        _ = await s.ReadAsync(buf, TestContext.Current.CancellationToken);

        var hash = await s.CompleteAsync(TestContext.Current.CancellationToken);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data)), hash);
        Assert.Equal(data.Length, s.BytesRead);
    }
}

public class ZipLimitInspectorTests
{
    private static readonly ArchiveLimits Small = new(MaxEntrySize: 1024 * 1024, MaxTotalSize: 3 * 1024 * 1024, MaxEntries: 10, MaxCompressionRatio: 1000);

    [Fact]
    public void Archive_within_limits_has_no_gap()
    {
        var zip = TestFiles.Zip(("a.txt", Encoding.UTF8.GetBytes("hello")), ("b.txt", new byte[100]));
        Assert.Null(ZipLimitInspector.FindCoverageGap(new MemoryStream(zip), Small));
    }

    [Fact]
    public void Oversized_entry_is_reported()
    {
        var zip = TestFiles.ZipWithZeros(2 * 1024 * 1024);
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(zip), Small with { MaxCompressionRatio = 1e9 });
        Assert.Contains("engine limit per entry", gap, StringComparison.Ordinal);
    }

    [Fact]
    public void High_compression_ratio_is_reported()
    {
        var zip = TestFiles.ZipWithZeros(512 * 1024);
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(zip), Small with { MaxCompressionRatio = 50 });
        Assert.Contains("decompression bomb", gap, StringComparison.Ordinal);
    }

    [Fact]
    public void Too_many_entries_is_reported()
    {
        var entries = Enumerable.Range(0, 11).Select(i => ($"f{i}.txt", new byte[] { 1 })).ToArray();
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(TestFiles.Zip(entries)), Small);
        Assert.Contains("11 entries", gap, StringComparison.Ordinal);
    }

    [Fact]
    public void Total_size_is_reported()
    {
        var mb = new byte[900 * 1024];
        Random.Shared.NextBytes(mb);
        var zip = TestFiles.Zip(("1", mb), ("2", mb), ("3", mb), ("4", mb));
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(zip), Small);
        Assert.Contains("in total", gap, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("PK\u0003\u0004garbage")]
    [InlineData("PK\u0003\u0004")]
    public void Corrupt_zip_is_reported_not_thrown(string content)
    {
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(Encoding.Latin1.GetBytes(content)), Small);
        Assert.Contains("could not be read", gap, StringComparison.Ordinal);
    }

    [Fact]
    public void Truncated_zip_is_reported_not_thrown()
    {
        var zip = TestFiles.Zip(("a.txt", new byte[5000]));
        var gap = ZipLimitInspector.FindCoverageGap(new MemoryStream(zip[..(zip.Length / 2)]), Small);
        Assert.NotNull(gap);
    }
}
