using UScan.Core.Model;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class EventLogTests
{
    private static SecurityEvent Ev(int i) =>
        new(DateTimeOffset.UnixEpoch.AddSeconds(i), EventSeverity.Info, "test", $"event {i}");

    [Fact]
    public void Events_are_read_back_newest_first()
    {
        using var dir = new TempDir();
        var log = new JsonLinesEventLog(dir.Path);
        for (var i = 0; i < 5; i++)
        {
            log.Append(Ev(i));
        }

        var read = log.ReadRecent();
        Assert.Equal(["event 4", "event 3", "event 2", "event 1", "event 0"], read.Select(e => e.Message));
    }

    [Fact]
    public void Rotation_keeps_at_most_max_files_and_newest_events()
    {
        using var dir = new TempDir();
        var log = new JsonLinesEventLog(dir.Path, maxFileBytes: 1024, maxFiles: 3);
        for (var i = 0; i < 200; i++)
        {
            log.Append(Ev(i));
        }

        Assert.True(Directory.GetFiles(dir.Path).Length <= 3);
        Assert.All(Directory.GetFiles(dir.Path), f => Assert.True(new FileInfo(f).Length <= 1024));
        var read = log.ReadRecent(10_000);
        Assert.Equal("event 199", read[0].Message);
        Assert.True(read.Count < 200);
    }

    [Fact]
    public void Corrupt_lines_are_skipped()
    {
        using var dir = new TempDir();
        var log = new JsonLinesEventLog(dir.Path);
        log.Append(Ev(1));
        File.AppendAllText(log.CurrentFile, "{\"Time\":\"broken\n<<<garbage>>>\n");
        log.Append(Ev(2));

        Assert.Equal(["event 2", "event 1"], log.ReadRecent().Select(e => e.Message));
    }

    [Fact]
    public void Concurrent_writers_do_not_lose_or_tear_lines()
    {
        using var dir = new TempDir();
        var log = new JsonLinesEventLog(dir.Path, maxFileBytes: 10 * 1024 * 1024);
        Parallel.For(0, 500, i => log.Append(Ev(i)));
        Assert.Equal(500, log.ReadRecent(10_000).Count);
    }
}

public class ReportStoreTests
{
    private static ScanReport Report(DateTimeOffset start) => new(
        Guid.NewGuid(), start, start.AddSeconds(3), ScanOutcome.Completed, ["/x"],
        new EngineInfo("clamav", "1.5.4", 1, start), 1,
        [new FileScanResult("/x/a", 68, TestFiles.EicarSha256, Verdict.Infected, SkipReason.None,
            [new EngineResult(Verdict.Infected, "clamav", "Test.EICAR", "stream: Test.EICAR FOUND")], null, TimeSpan.FromMilliseconds(5))],
        []);

    [Fact]
    public void Saved_report_round_trips()
    {
        using var dir = new TempDir();
        var store = new ReportStore(dir.Path);
        var original = Report(DateTimeOffset.UtcNow);
        var path = store.Save(original);

        var loaded = store.Load(path)!;
        Assert.Equal(original.ScanId, loaded.ScanId);
        Assert.Equal(Verdict.Infected, loaded.Files[0].Verdict);
        Assert.Equal("Test.EICAR", loaded.Files[0].DetectionName);
        Assert.True(loaded.ThreatsFound);
    }

    [Fact]
    public void Old_reports_are_pruned_and_no_temp_files_remain()
    {
        using var dir = new TempDir();
        var store = new ReportStore(dir.Path, keep: 3);
        for (var i = 0; i < 6; i++)
        {
            store.Save(Report(DateTimeOffset.UnixEpoch.AddDays(i)));
        }

        Assert.Equal(3, store.List().Count);
        Assert.Contains("19700106", Path.GetFileName(store.List()[0]), StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(dir.Path, "*.tmp"));
    }

    [Fact]
    public void Corrupt_report_loads_as_null()
    {
        using var dir = new TempDir();
        var path = dir.Write("bad.json", "{ not json");
        Assert.Null(new ReportStore(dir.Path).Load(path));
    }
}
