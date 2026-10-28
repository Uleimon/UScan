using Microsoft.Extensions.Time.Testing;
using UScan.Core.Inventory;
using UScan.Core.Model;
using UScan.Core.Monitoring;
using UScan.Core.Scanning;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class ChangeDebouncerTests
{
    [Fact]
    public void Path_is_released_only_after_changes_settle()
    {
        var time = new FakeTimeProvider();
        var d = new ChangeDebouncer(TimeSpan.FromSeconds(2), time);
        d.Touch("a");
        time.Advance(TimeSpan.FromSeconds(1.5));
        d.Touch("a");
        time.Advance(TimeSpan.FromSeconds(1.5));
        Assert.Empty(d.TakeSettled());
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(["a"], d.TakeSettled());
        Assert.Equal(0, d.Count);
    }

    [Fact]
    public void Queue_limit_is_enforced_and_deleted_files_are_forgotten()
    {
        var d = new ChangeDebouncer(TimeSpan.Zero, new FakeTimeProvider());
        Assert.True(d.Touch("a", 2));
        Assert.True(d.Touch("b", 2));
        Assert.False(d.Touch("c", 2));
        Assert.True(d.Touch("a", 2));
        d.Forget("b");
        Assert.Equal(["a"], d.TakeSettled());
    }
}

public class MassChangeDetectorTests
{
    [Fact]
    public void Alarm_fires_once_per_window_and_counts_distinct_files()
    {
        var time = new FakeTimeProvider();
        var m = new MassChangeDetector(5, TimeSpan.FromSeconds(60), time);
        for (var i = 0; i < 20; i++)
        {
            Assert.False(m.Record("same-file"));
        }

        var alarms = Enumerable.Range(0, 10).Count(i => m.Record($"f{i}"));
        Assert.Equal(1, alarms);

        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(0, m.CurrentCount);
        Assert.Equal(1, Enumerable.Range(0, 10).Count(i => m.Record($"g{i}")));
    }
}

public sealed class FileWatchServiceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new();

    public void Dispose() => _dir.Dispose();

    private FileWatchService Service(FakeEngine engine, WatchOptions? options = null, JsonLinesEventLog? log = null) =>
        new([_dir.Path], new ScanRunner(engine), options ?? new WatchOptions { SettleDelay = TimeSpan.FromSeconds(2) }, log, _time);

    [Fact]
    public async Task Changed_file_is_scanned_after_settling_and_detection_is_logged()
    {
        var log = new JsonLinesEventLog(Path.Combine(_dir.Path, "..", Guid.NewGuid().ToString("N")));
        var svc = Service(new FakeEngine(), log: log);
        var results = new List<FileScanResult>();
        svc.FileScanned += results.Add;

        var bad = _dir.Write("eicar.com", TestFiles.Eicar);
        var good = _dir.Write("ok.txt", "hello");
        svc.OnChanged(bad);
        svc.OnChanged(good);

        await svc.ProcessDueAsync(TestContext.Current.CancellationToken);
        Assert.Empty(results);

        _time.Advance(TimeSpan.FromSeconds(3));
        await svc.ProcessDueAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, results.Count);
        Assert.Equal(Verdict.Infected, results.Single(r => r.Path == bad).Verdict);
        Assert.Equal(2, svc.Status.FilesScanned);
        Assert.Equal(1, svc.Status.Detections);
        Assert.Contains(log.ReadRecent(), e => e.Severity == EventSeverity.Threat && e.Path == bad);
    }

    [Fact]
    public async Task Excluded_folders_and_deleted_files_are_ignored()
    {
        var excluded = Path.Combine(_dir.Path, "uscan-data");
        var svc = Service(new FakeEngine(), new WatchOptions { SettleDelay = TimeSpan.Zero, Exclusions = [excluded] });
        var scanned = 0;
        svc.FileScanned += _ => scanned++;

        svc.OnChanged(_dir.Write(Path.Combine("uscan-data", "q.bin"), TestFiles.Eicar));
        svc.OnChanged(Path.Combine(_dir.Path, "gone.txt"));
        await svc.ProcessDueAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, scanned);
        Assert.Equal(0, svc.Status.Pending);
    }

    [Fact]
    public async Task Unavailable_engine_keeps_files_queued()
    {
        var svc = Service(new FakeEngine { Unavailable = true }, new WatchOptions { SettleDelay = TimeSpan.Zero });
        var warnings = new List<string>();
        svc.Warning += warnings.Add;
        svc.OnChanged(_dir.Write("a.txt", "x"));
        await svc.ProcessDueAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, svc.Status.Pending);
        Assert.Equal(0, svc.Status.FilesScanned);
        Assert.Contains(warnings, w => w.Contains("unavailable", StringComparison.Ordinal));
    }

    [Fact]
    public void Mass_change_and_queue_overflow_raise_warnings()
    {
        var svc = Service(new FakeEngine(), new WatchOptions { MassChangeThreshold = 10, MaxPending = 5 });
        var warnings = new List<string>();
        svc.Warning += warnings.Add;
        for (var i = 0; i < 12; i++)
        {
            svc.OnChanged(Path.Combine(_dir.Path, $"f{i}.locked"));
        }

        Assert.Contains(warnings, w => w.Contains("ransomware", StringComparison.Ordinal));
        Assert.Contains(warnings, w => w.Contains("manual scan", StringComparison.Ordinal));
        Assert.Equal(7, svc.Status.LostEvents);
    }

    [Fact]
    public async Task Real_file_system_watcher_triggers_rescan()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var svc = new FileWatchService([_dir.Path], new ScanRunner(new FakeEngine()), new WatchOptions { SettleDelay = TimeSpan.FromMilliseconds(300) });
        var detected = new TaskCompletionSource<FileScanResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        svc.FileScanned += r =>
        {
            if (r.Verdict == Verdict.Infected)
            {
                detected.TrySetResult(r);
            }
        };
        svc.Start();
        Assert.True(svc.Status.Running);

        var path = _dir.Write(Path.Combine("sub", "dropped.com"), TestFiles.Eicar);
        var r = await detected.Task.WaitAsync(TimeSpan.FromSeconds(20), ct);
        Assert.Equal(path, r.Path);

        await svc.StopAsync();
        Assert.False(svc.Status.Running);
    }
}

public class AutostartMonitorTests
{
    private sealed class ListSource(List<InventoryEntry> entries) : IInventorySource
    {
        public string Name => "list";
        public IEnumerable<InventoryEntry> Collect(ICollection<string> errors) => entries.ToList();
    }

    private static InventoryEntry E(string name, string cmd, SignatureStatus sig = SignatureStatus.NotSigned) =>
        new(InventoryKind.RegistryRun, "HKCU\\Run", name, cmd, cmd, true, null, new SignatureInfo(sig, null, null), []);

    [Fact]
    public void First_check_creates_baseline_then_changes_are_reported_and_logged()
    {
        using var dir = new TempDir();
        var entries = new List<InventoryEntry> { E("Updater", "C:\\A\\up.exe", SignatureStatus.Valid) };
        var log = new JsonLinesEventLog(Path.Combine(dir.Path, "logs"));
        var monitor = new AutostartMonitor(new InventoryCollector([new ListSource(entries)]), Path.Combine(dir.Path, "baselines", "autostart.json"), log);

        Assert.True(monitor.Check().BaselineCreated);
        Assert.Empty(monitor.Check().Changes);

        entries.Add(E("Evil", "C:\\Users\\x\\AppData\\Roaming\\e.exe"));
        entries[0] = E("Updater", "C:\\B\\up.exe", SignatureStatus.Valid);
        var check = monitor.Check();
        Assert.Contains(check.Changes, c => c.ChangeType == "Added" && c.Entry.Name == "Evil");
        Assert.Contains(check.Changes, c => c.ChangeType == "Modified" && c.Previous!.Command == "C:\\A\\up.exe");
        Assert.Contains(log.ReadRecent(), e => e.Severity == EventSeverity.Warning && e.Message.Contains("Evil", StringComparison.Ordinal));

        Assert.Empty(monitor.Check().Changes);
    }

    [Fact]
    public void Corrupt_baseline_is_recreated()
    {
        using var dir = new TempDir();
        var file = dir.Write("autostart.json", "{not json");
        var monitor = new AutostartMonitor(new InventoryCollector([new ListSource([E("a", "b")])]), file);
        Assert.True(monitor.Check().BaselineCreated);
        Assert.False(monitor.Check().BaselineCreated);
    }
}

public class MonitorHeartbeatTests
{
    [Fact]
    public void Fresh_heartbeat_is_active_stale_or_missing_is_not()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "run", "monitor.heartbeat");
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 28, 12, 0, 0, TimeSpan.Zero));
        Assert.Null(MonitorHeartbeat.ReadActive(file, time));

        MonitorHeartbeat.Write(file, ["C:\\Users\\a\\Downloads"], time);
        Assert.Equal(["C:\\Users\\a\\Downloads"], MonitorHeartbeat.ReadActive(file, time));

        time.Advance(TimeSpan.FromMinutes(5));
        Assert.Null(MonitorHeartbeat.ReadActive(file, time));

        MonitorHeartbeat.Clear(file);
        Assert.False(File.Exists(file));
    }
}
