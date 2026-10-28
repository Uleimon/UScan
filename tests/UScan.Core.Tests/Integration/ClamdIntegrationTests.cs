using System.Text;
using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Integration;

[Trait("Category", "Integration")]
public class ClamdIntegrationTests(ClamdFixture clamd) : IClassFixture<ClamdFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private void SkipIfUnavailable()
    {
        if (clamd.SkipReason is { } reason)
        {
            Assert.Skip(reason);
        }
    }

    private async Task<FileScanResult> ScanSingle(byte[] content, string name = "sample.bin")
    {
        using var dir = new TempDir();
        dir.Write(name, content);
        var report = await new ScanRunner(clamd.CreateEngine(), new ScanOptions { ArchiveLimits = clamd.ArchiveLimits })
            .RunAsync([dir.Path], cancellationToken: Ct);
        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        return Assert.Single(report.Files);
    }

    [Fact]
    public async Task Reports_engine_version()
    {
        SkipIfUnavailable();
        var info = await clamd.CreateEngine().GetInfoAsync(Ct);
        Assert.Matches(@"^\d+\.\d+", info.EngineVersion);
    }

    [Fact]
    public async Task Detects_eicar()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(TestFiles.Eicar, "eicar.com");
        Assert.Equal(Verdict.Infected, r.Verdict);
        Assert.Equal("UScan.Test.EICAR.UNOFFICIAL", r.DetectionName);
        Assert.Equal(TestFiles.EicarSha256, r.Sha256);
    }

    [Fact]
    public async Task Detects_eicar_inside_zip()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(TestFiles.Zip(("docs/eicar.com", TestFiles.Eicar)), "archive.zip");
        Assert.Equal(Verdict.Infected, r.Verdict);
    }

    [Fact]
    public async Task Detects_eicar_three_zip_levels_deep()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(TestFiles.NestedZip(TestFiles.Eicar, "eicar.com", 3), "nested.zip");
        Assert.Equal(Verdict.Infected, r.Verdict);
    }

    [Fact]
    public async Task Recursion_beyond_limit_is_incomplete_not_clean()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(TestFiles.NestedZip(Encoding.ASCII.GetBytes("harmless"), "a.txt", ClamdFixture.MaxRecursion + 3), "deep.zip");
        Assert.Equal(Verdict.Incomplete, r.Verdict);
        Assert.StartsWith("Heuristics.Limits.Exceeded", r.DetectionName, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Too_many_archive_entries_is_incomplete()
    {
        SkipIfUnavailable();
        var entries = Enumerable.Range(0, ClamdFixture.MaxFiles + 50).Select(i => ($"f{i}.txt", new byte[] { (byte)'x' })).ToArray();
        var r = await ScanSingle(TestFiles.Zip(entries), "many.zip");
        Assert.Equal(Verdict.Incomplete, r.Verdict);
    }

    /// <summary>
    /// Regression test for a real ClamAV behaviour found during development: an oversized ZIP member is
    /// silently truncated to MaxFileSize and clamd answers "OK". UScan must not show this as clean.
    /// </summary>
    [Fact]
    public async Task Oversized_zip_member_is_incomplete_not_clean()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(TestFiles.ZipWithZeros(ClamdFixture.MaxFileSize + 5 * 1024 * 1024), "bomb.zip");
        Assert.Equal(Verdict.Incomplete, r.Verdict);
        Assert.NotNull(r.Message);
    }

    [Fact]
    public async Task Corrupt_zip_is_handled_and_not_reported_clean()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(Encoding.Latin1.GetBytes("PK\u0003\u0004this-is-not-a-valid-zip"), "corrupt.zip");
        Assert.Equal(Verdict.Incomplete, r.Verdict);
        Assert.Contains("could not be read", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Stream_above_engine_limit_is_skipped()
    {
        SkipIfUnavailable();
        var r = await ScanSingle(new byte[ClamdFixture.StreamMaxLength + 1], "huge.bin");
        Assert.Equal(Verdict.Skipped, r.Verdict);
        Assert.Equal(SkipReason.TooLarge, r.SkipReason);
    }

    /// <summary>Small false-positive check: varied benign content must not be flagged.</summary>
    [Fact]
    public async Task Benign_corpus_produces_no_detections()
    {
        SkipIfUnavailable();
        using var dir = new TempDir();
        var rng = new Random(12345);
        for (var i = 0; i < 40; i++)
        {
            var bytes = new byte[rng.Next(0, 200_000)];
            rng.NextBytes(bytes);
            dir.Write($"random/{i}.bin", bytes);
        }

        dir.Write("text/lorem.txt", string.Concat(Enumerable.Repeat("Lorem ipsum dolor sit amet. ", 5000)));
        dir.Write("text/script.ps1", "Get-ChildItem -Path $env:TEMP | Select-Object Name\n");
        dir.Write("text/near-eicar.txt", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE is mentioned here but this is not the test file.");
        dir.Write("archives/docs.zip", TestFiles.Zip(("a.txt", Encoding.UTF8.GetBytes("hello")), ("b/c.txt", new byte[1000])));
        dir.Write("empty.dat", []);

        var report = await new ScanRunner(clamd.CreateEngine(), new ScanOptions { ArchiveLimits = clamd.ArchiveLimits })
            .RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        Assert.Equal(45, report.Files.Count);
        Assert.All(report.Files, f => Assert.Equal(Verdict.Clean, f.Verdict));
    }
}
