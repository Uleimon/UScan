using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class ScanRunnerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Clean_and_infected_files_are_classified_with_hashes()
    {
        using var dir = new TempDir();
        var clean = dir.Write("docs/readme.txt", "harmless");
        var bad = dir.Write("sub/deeper/eicar.com", TestFiles.Eicar);

        var report = await new ScanRunner(new FakeEngine()).RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        Assert.Equal(2, report.FilesDiscovered);
        Assert.Equal(0, report.FilesNotProcessed);
        var badResult = Assert.Single(report.Files, f => f.Path == bad);
        Assert.Equal(Verdict.Infected, badResult.Verdict);
        Assert.Equal(TestFiles.EicarSha256, badResult.Sha256);
        Assert.Equal(68, badResult.SizeBytes);
        Assert.Equal(Verdict.Clean, Assert.Single(report.Files, f => f.Path == clean).Verdict);
        Assert.True(report.ThreatsFound);
    }

    [Fact]
    public async Task Symlinks_are_not_followed_and_are_reported()
    {
        using var dir = new TempDir();
        using var outside = new TempDir();
        dir.Write("a.txt", "x");
        outside.Write("eicar.com", TestFiles.Eicar);
        var fileLink = Path.Combine(dir.Path, "link-to-eicar");
        var dirLink = Path.Combine(dir.Path, "link-to-dir");
        File.CreateSymbolicLink(fileLink, Path.Combine(outside.Path, "eicar.com"));
        Directory.CreateSymbolicLink(dirLink, outside.Path);

        var engine = new FakeEngine();
        var report = await new ScanRunner(engine).RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(1, engine.Scans);
        Assert.All(report.Files.Where(f => f.Path != Path.Combine(dir.Path, "a.txt")), f =>
        {
            Assert.Equal(Verdict.Skipped, f.Verdict);
            Assert.Equal(SkipReason.ReparsePointOrSymlink, f.SkipReason);
        });
        Assert.Equal(3, report.Files.Count);
        Assert.False(report.ThreatsFound);
    }

    [Fact]
    public async Task Files_over_engine_limit_are_skipped_not_clean()
    {
        using var dir = new TempDir();
        dir.Write("big.bin", new byte[2048]);
        var report = await new ScanRunner(new FakeEngine { MaxStreamBytes = 1024 }).RunAsync([dir.Path], cancellationToken: Ct);

        var r = Assert.Single(report.Files);
        Assert.Equal(Verdict.Skipped, r.Verdict);
        Assert.Equal(SkipReason.TooLarge, r.SkipReason);
    }

    [Fact]
    public async Task Read_errors_are_recorded_per_file_and_scan_continues()
    {
        using var dir = new TempDir();
        var locked = dir.Write("locked.bin", "x");
        dir.Write("ok.txt", "y");
        var options = new ScanOptions
        {
            OpenFile = p => p == locked ? throw new UnauthorizedAccessException("Access denied (simulated)") : ScanOptions.OpenForScan(p),
        };

        var report = await new ScanRunner(new FakeEngine(), options).RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        var err = Assert.Single(report.Files, f => f.Path == locked);
        Assert.Equal(Verdict.Error, err.Verdict);
        Assert.Contains("Access denied", err.Message, StringComparison.Ordinal);
        Assert.Equal(Verdict.Clean, Assert.Single(report.Files, f => f.Path != locked).Verdict);
    }

    [Fact]
    public async Task Missing_root_is_an_issue_not_a_crash()
    {
        var report = await new ScanRunner(new FakeEngine()).RunAsync(["/definitely/not/here"], cancellationToken: Ct);
        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        Assert.Empty(report.Files);
        Assert.Contains(report.Issues, i => i.Message.Contains("does not exist", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancellation_leaves_unprocessed_files_unclassified()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 50; i++)
        {
            dir.Write($"f{i:D2}.txt", "data");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var engine = new FakeEngine { DelayPerFile = TimeSpan.FromMilliseconds(50) };
        var progress = new SyncProgress(p =>
        {
            if (p.FilesCompleted >= 5)
            {
                cts.Cancel();
            }
        });

        var report = await new ScanRunner(engine, new ScanOptions { MaxDegreeOfParallelism = 1 }).RunAsync([dir.Path], progress, cts.Token);

        Assert.Equal(ScanOutcome.Cancelled, report.Outcome);
        Assert.InRange(report.Files.Count, 5, 49);
        Assert.True(report.FilesNotProcessed > 0);
        Assert.All(report.Files, f => Assert.Equal(Verdict.Clean, f.Verdict));
    }

    [Fact]
    public async Task Engine_failure_mid_scan_aborts_and_is_reported()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 10; i++)
        {
            dir.Write($"f{i}.txt", "data");
        }

        var report = await new ScanRunner(new FakeEngine { FailAfterScans = 3 }, new ScanOptions { MaxDegreeOfParallelism = 1, EngineRecoveryDelay = TimeSpan.Zero })
            .RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Aborted, report.Outcome);
        Assert.Contains(report.Issues, i => i.Message.Contains("crashed", StringComparison.Ordinal) && i.Message.Contains("still unreachable after 24 attempts", StringComparison.Ordinal) && i.Message.Contains(dir.Path, StringComparison.Ordinal));
        Assert.True(report.FilesNotProcessed > 0);
    }

    [Fact]
    public async Task Single_dropped_connection_is_retried_and_the_scan_completes()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 5; i++)
        {
            dir.Write($"f{i}.txt", "data");
        }

        var bad = dir.Write("eicar.com", TestFiles.Eicar);
        var engine = new FakeEngine { DropScans = new HashSet<int> { 2 } };
        var report = await new ScanRunner(engine, new ScanOptions { MaxDegreeOfParallelism = 1, EngineRecoveryDelay = TimeSpan.Zero })
            .RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        Assert.Equal(6, report.Files.Count);
        Assert.Equal(0, report.FilesNotProcessed);
        Assert.Equal(7, engine.Scans);
        Assert.Equal(Verdict.Infected, Assert.Single(report.Files, f => f.Path == bad).Verdict);
        Assert.Equal(5, report.CountOf(Verdict.Clean));
    }

    [Fact]
    public async Task File_that_the_engine_keeps_dropping_is_an_error_not_clean_and_the_scan_goes_on()
    {
        using var dir = new TempDir();
        var odd = dir.Write("odd.bin", "DROPME");
        dir.Write("ok.txt", "data");
        var report = await new ScanRunner(new FakeEngine { AlwaysDropMarker = "DROPME" }, new ScanOptions { EngineRecoveryDelay = TimeSpan.Zero })
            .RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        var r = Assert.Single(report.Files, f => f.Path == odd);
        Assert.Equal(Verdict.Error, r.Verdict);
        Assert.Contains("twice", r.Message, StringComparison.Ordinal);
        Assert.Equal(1, report.CountOf(Verdict.Clean));
    }

    [Fact]
    public async Task Engine_that_is_briefly_gone_again_after_recovering_does_not_abort_the_scan()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 5; i++)
        {
            dir.Write($"f{i}.txt", "data");
        }

        // Scan 2 and its retry (scan 3) both fail, and each time the engine is unreachable for 3 checks.
        var engine = new FakeEngine { DropScans = new HashSet<int> { 2, 3 }, OfflineChecksAfterDrop = 3 };
        var report = await new ScanRunner(engine, new ScanOptions { MaxDegreeOfParallelism = 1, EngineRecoveryDelay = TimeSpan.Zero })
            .RunAsync([dir.Path], cancellationToken: Ct);

        Assert.Equal(ScanOutcome.Completed, report.Outcome);
        Assert.Equal(5, report.Files.Count);
        Assert.Equal(1, report.CountOf(Verdict.Error));
        Assert.Equal(4, report.CountOf(Verdict.Clean));
    }

    [Fact]
    public async Task Unavailable_engine_aborts_before_scanning()
    {
        using var dir = new TempDir();
        dir.Write("a.txt", "x");
        var report = await new ScanRunner(new FakeEngine { Unavailable = true }).RunAsync([dir.Path], cancellationToken: Ct);
        Assert.Equal(ScanOutcome.Aborted, report.Outcome);
        Assert.Null(report.Engine);
        Assert.Empty(report.Files);
    }

    [Fact]
    public async Task Progress_fraction_is_unknown_until_enumeration_finished_and_ends_at_one()
    {
        using var dir = new TempDir();
        for (var i = 0; i < 20; i++)
        {
            dir.Write($"f{i}.txt", "data");
        }

        var seen = new List<ScanProgress>();
        await new ScanRunner(new FakeEngine()).RunAsync([dir.Path], new SyncProgress(p => { lock (seen) { seen.Add(p); } }), Ct);

        Assert.All(seen.Where(p => !p.EnumerationComplete), p => Assert.Null(p.Fraction));
        var last = seen[^1];
        Assert.True(last.EnumerationComplete);
        Assert.Equal(1.0, last.Fraction);
        Assert.Equal(20, last.FilesCompleted);
        Assert.All(seen, p => Assert.True(p.FilesCompleted <= p.FilesDiscovered));
    }

    [Fact]
    public async Task Clean_zip_beyond_limits_is_reported_incomplete()
    {
        using var dir = new TempDir();
        dir.Write("bomb.zip", TestFiles.ZipWithZeros(3 * 1024 * 1024));
        var options = new ScanOptions { ArchiveLimits = new ArchiveLimits(1024 * 1024, 10 * 1024 * 1024, 100, 1e9) };

        var report = await new ScanRunner(new FakeEngine(), options).RunAsync([dir.Path], cancellationToken: Ct);

        var r = Assert.Single(report.Files);
        Assert.Equal(Verdict.Incomplete, r.Verdict);
        Assert.Contains("Only a part was scanned", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Directory_depth_limit_is_reported()
    {
        using var dir = new TempDir();
        dir.Write("a/b/c/d/e.txt", "x");
        var report = await new ScanRunner(new FakeEngine(), new ScanOptions { MaxDirectoryDepth = 2 }).RunAsync([dir.Path], cancellationToken: Ct);
        Assert.Empty(report.Files);
        Assert.Contains(report.Issues, i => i.Message.Contains("depth limit", StringComparison.Ordinal));
    }

    /// <summary>Progress&lt;T&gt; posts to the thread pool; this reports synchronously for deterministic tests.</summary>
    private sealed class SyncProgress(Action<ScanProgress> onReport) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => onReport(value);
    }
}
