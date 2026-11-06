using System.Text;
using UScan.Core.App;
using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class ScanJournalTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ScanJournalHeader Header(string root) => new(DateTimeOffset.UtcNow, ScanMode.Custom, [root], 64, []);

    [Fact]
    public async Task Interrupted_scan_continues_and_only_scans_new_or_changed_files()
    {
        using var dir = new TempDir();
        var files = Path.Combine(dir.Path, "files");
        for (var i = 0; i < 10; i++)
        {
            dir.Write($"files/f{i}.txt", $"data {i}");
        }

        var journalDir = Path.Combine(dir.Path, "journal");

        // First run: the engine dies after 3 files, like a PC that is switched off mid-scan.
        ScanReport first;
        using (var journal = ScanJournal.Start(journalDir, Header(files)))
        {
            first = await new ScanRunner(new FakeEngine { FailAfterScans = 3 }, new ScanOptions { MaxDegreeOfParallelism = 1, EngineRecoveryDelay = TimeSpan.Zero, Journal = journal })
                .RunAsync([files], cancellationToken: Ct);
        }

        Assert.Equal(ScanOutcome.Aborted, first.Outcome);
        var peek = Assert.IsType<InterruptedScan>(ScanJournal.Peek(journalDir));
        Assert.Equal(3, peek.FilesDone);

        // One of the checked files changes in the meantime: it must be scanned again.
        var changed = first.Files.First(f => f.Verdict == Verdict.Clean).Path;
        await File.WriteAllTextAsync(changed, "changed content", Ct);
        File.SetLastWriteTimeUtc(changed, DateTime.UtcNow.AddMinutes(5));

        var engine = new FakeEngine();
        ScanReport second;
        using (var journal = ScanJournal.Resume(journalDir)!)
        {
            Assert.Equal(3, journal.PreviouslyDone);
            second = await new ScanRunner(engine, new ScanOptions { MaxDegreeOfParallelism = 1, EngineRecoveryDelay = TimeSpan.Zero, Journal = journal }).RunAsync([files], cancellationToken: Ct);
        }

        Assert.Equal(ScanOutcome.Completed, second.Outcome);
        Assert.Equal(10, second.Files.Count);
        Assert.Equal(10 - 3 + 1, engine.Scans);
        Assert.Equal(10, second.CountOf(Verdict.Clean));
    }

    [Fact]
    public void A_line_cut_off_by_a_power_loss_is_ignored_and_errors_are_not_reused()
    {
        using var dir = new TempDir();
        var file = dir.Write("a.txt", "x");
        var journalDir = Path.Combine(dir.Path, "journal");
        var stamp = File.GetLastWriteTimeUtc(file);
        using (var journal = ScanJournal.Start(journalDir, Header(dir.Path)))
        {
            journal.Append(new FileScanResult(file, 1, null, Verdict.Error, SkipReason.None, [], "locked", TimeSpan.Zero), stamp);
        }

        File.AppendAllText(Path.Combine(journalDir, "files.jsonl"), "{\"result\":{\"path\":\"C:\\\\half", Encoding.UTF8);

        Assert.Equal(1, ScanJournal.Peek(journalDir)!.FilesDone);
        using var resumed = ScanJournal.Resume(journalDir)!;
        Assert.Null(resumed.TryReuse(file, stamp));
    }

    [Fact]
    public void Discarding_a_scan_that_ended_without_report_saves_its_detections()
    {
        using var dir = new TempDir();
        var host = new UScanHost(new AppPaths(Path.Combine(dir.Path, "data")), new GenericPlatformServices());
        var bad = dir.Write("bad.exe", "payload");
        using (var journal = ScanJournal.Start(host.InterruptedScanDirectory, Header(dir.Path)))
        {
            journal.Append(new FileScanResult(bad, 7, new string('a', 64), Verdict.Infected, SkipReason.None,
                [new EngineResult(Verdict.Infected, "clamav", "Test.Sig", null)], null, TimeSpan.Zero), File.GetLastWriteTimeUtc(bad));
        }

        Assert.Equal(1, host.InterruptedScan()!.Detections);
        Assert.Empty(host.OpenDetections());

        var report = host.DiscardInterrupted();

        Assert.NotNull(report);
        Assert.Null(host.InterruptedScan());
        Assert.Equal(ScanOutcome.Aborted, host.Reports.Load(report)!.Outcome);
        Assert.Equal(bad, Assert.Single(host.OpenDetections()).Path);
        Assert.Contains(host.Log.ReadRecent(10), e => e.Severity == EventSeverity.Threat && e.Path == bad);
    }
}
