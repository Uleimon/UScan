using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Storage;

namespace UScan.Core.Monitoring;

public sealed record WatchOptions
{
    /// <summary>A file is scanned once no further change was seen for this long (writers usually finish in bursts).</summary>
    public TimeSpan SettleDelay { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Upper bound of queued paths; beyond it events are dropped and reported as lost.</summary>
    public int MaxPending { get; init; } = 10_000;

    /// <summary>Distinct files changed within <see cref="MassChangeWindow"/> that raise the mass-change warning.</summary>
    public int MassChangeThreshold { get; init; } = 300;

    public TimeSpan MassChangeWindow { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>A file whose scan failed (typically still locked by its writer) is retried this often.</summary>
    public int MaxRetries { get; init; } = 3;

    /// <summary>Directories never watched, e.g. UScan's own data folder (quarantine, logs) to avoid feedback loops.</summary>
    public IReadOnlyList<string> Exclusions { get; init; } = [];
}

/// <summary>Pending changed paths with a settle delay, so a file being written is scanned once, after it is complete.</summary>
public sealed class ChangeDebouncer(TimeSpan settle, TimeProvider time)
{
    private static readonly StringComparer PathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private readonly Dictionary<string, DateTimeOffset> _pending = new(PathComparer);
    private readonly Lock _gate = new();

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    /// <returns>false if the path was new and the queue is full.</returns>
    public bool Touch(string path, int maxPending = int.MaxValue)
    {
        lock (_gate)
        {
            if (!_pending.ContainsKey(path) && _pending.Count >= maxPending)
            {
                return false;
            }

            _pending[path] = time.GetUtcNow();
            return true;
        }
    }

    public void Forget(string path)
    {
        lock (_gate)
        {
            _pending.Remove(path);
        }
    }

    public IReadOnlyList<string> TakeSettled(int max = int.MaxValue)
    {
        var due = time.GetUtcNow() - settle;
        lock (_gate)
        {
            var ready = _pending.Where(kv => kv.Value <= due).OrderBy(kv => kv.Value).Take(max).Select(kv => kv.Key).ToList();
            foreach (var p in ready)
            {
                _pending.Remove(p);
            }

            return ready;
        }
    }
}

/// <summary>
/// Counts distinct files changed in a sliding window. Many changes in a short time are a
/// <em>possible</em> sign of ransomware encrypting files, but also of backups, builds or
/// unpacking. It is therefore only an indicator, never a detection, and nothing is blocked.
/// </summary>
public sealed class MassChangeDetector(int threshold, TimeSpan window, TimeProvider time)
{
    private readonly Queue<(DateTimeOffset Time, string Path)> _events = new();
    private readonly Dictionary<string, int> _counts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private DateTimeOffset _lastAlarm = DateTimeOffset.MinValue;

    public int CurrentCount
    {
        get
        {
            lock (_gate)
            {
                Expire(time.GetUtcNow());
                return _counts.Count;
            }
        }
    }

    /// <returns>true exactly once per window when the threshold is crossed.</returns>
    public bool Record(string path)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            Expire(now);
            _events.Enqueue((now, path));
            _counts[path] = _counts.GetValueOrDefault(path) + 1;
            if (_counts.Count >= threshold && now - _lastAlarm >= window)
            {
                _lastAlarm = now;
                return true;
            }

            return false;
        }
    }

    private void Expire(DateTimeOffset now)
    {
        while (_events.Count > 0 && now - _events.Peek().Time > window)
        {
            var (_, p) = _events.Dequeue();
            if (--_counts[p] == 0)
            {
                _counts.Remove(p);
            }
        }
    }
}

public sealed record WatchStatus(
    bool Running,
    IReadOnlyList<string> Roots,
    long FilesScanned,
    long Detections,
    long LostEvents,
    int Pending,
    string? LastError);

/// <summary>
/// Re-scans files shortly after they were created, changed or renamed.
/// <para>
/// Limits, stated plainly: this is <b>not</b> on-access blocking. UScan has no file-system
/// minifilter driver, so a file can be opened or executed before its scan finishes. Windows
/// can drop change notifications when its buffer overflows; such losses are counted and
/// logged so the user knows a manual scan is needed. Real blocking protection on Windows
/// comes from Microsoft Defender's real-time protection, which UScan never switches off.
/// </para>
/// </summary>
public sealed class FileWatchService : IAsyncDisposable
{
    private readonly IReadOnlyList<string> _roots;
    private readonly ScanRunner _runner;
    private readonly WatchOptions _options;
    private readonly JsonLinesEventLog? _log;
    private readonly TimeProvider _time;
    private readonly ChangeDebouncer _debouncer;
    private readonly MassChangeDetector _massChange;
    private readonly string[] _exclusions;
    private readonly Dictionary<string, int> _retries = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private long _scanned;
    private long _detections;
    private long _lost;
    private string? _lastError;

    public FileWatchService(IReadOnlyList<string> roots, ScanRunner runner, WatchOptions? options = null, JsonLinesEventLog? log = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(runner);
        _roots = roots.Select(Path.GetFullPath).ToArray();
        _runner = runner;
        _options = options ?? new WatchOptions();
        _log = log;
        _time = time ?? TimeProvider.System;
        _debouncer = new ChangeDebouncer(_options.SettleDelay, _time);
        _massChange = new MassChangeDetector(_options.MassChangeThreshold, _options.MassChangeWindow, _time);
        _exclusions = _options.Exclusions.Select(e => Path.TrimEndingDirectorySeparator(Path.GetFullPath(e)) + Path.DirectorySeparatorChar).ToArray();
    }

    /// <summary>Raised for every completed scan of a changed file.</summary>
    public event Action<FileScanResult>? FileScanned;

    /// <summary>Raised for warnings the user should see (mass change, lost events, watcher failure).</summary>
    public event Action<string>? Warning;

    public WatchStatus Status => new(
        _loop is { IsCompleted: false },
        _roots,
        Interlocked.Read(ref _scanned),
        Interlocked.Read(ref _detections),
        Interlocked.Read(ref _lost),
        _debouncer.Count,
        _lastError);

    public void Start()
    {
        if (_loop is not null)
        {
            throw new InvalidOperationException("Already started.");
        }

        foreach (var root in _roots)
        {
            if (!Directory.Exists(root))
            {
                throw new DirectoryNotFoundException($"Watch root does not exist: {root}");
            }

            var w = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            w.Created += (_, e) => OnChanged(e.FullPath);
            w.Changed += (_, e) => OnChanged(e.FullPath);
            w.Renamed += (_, e) =>
            {
                _debouncer.Forget(e.OldFullPath);
                OnChanged(e.FullPath);
            };
            w.Deleted += (_, e) => _debouncer.Forget(e.FullPath);
            w.Error += (_, e) => OnWatcherError(root, e.GetException());
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }

        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        Log(EventSeverity.Info, $"File monitoring started for {string.Join(", ", _roots)} (re-scan after change; no blocking).");
    }

    public async Task StopAsync()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }

        _watchers.Clear();
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
            try
            {
                await (_loop ?? Task.CompletedTask).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _cts.Dispose();
            _cts = null;
            Log(EventSeverity.Info, "File monitoring stopped.");
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    internal void OnChanged(string path)
    {
        if (IsExcluded(path))
        {
            return;
        }

        if (Directory.Exists(path))
        {
            // A new or renamed folder: files created in it before the watcher picked it up
            // produce no event of their own, so they are queued here.
            EnqueueDirectory(path);
            return;
        }

        if (_massChange.Record(path))
        {
            Warn($"{_massChange.CurrentCount} files changed within {_options.MassChangeWindow.TotalSeconds:0} s. This can be normal (backup, build, unpacking) " +
                 "but is also typical for ransomware. Check which program is writing; UScan does not block it.");
        }

        if (!_debouncer.Touch(path, _options.MaxPending))
        {
            if (Interlocked.Increment(ref _lost) == 1)
            {
                Warn($"More than {_options.MaxPending} changed files are queued; further changes are not scanned. Run a manual scan afterwards.");
            }
        }
    }

    private void EnqueueDirectory(string dir)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }).Take(_options.MaxPending))
            {
                OnChanged(f);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Folder vanished or is unreadable; its own events (if any) still arrive.
        }
    }

    private void OnWatcherError(string root, Exception ex)
    {
        Interlocked.Increment(ref _lost);
        _lastError = ex.Message;
        Warn(ex is InternalBufferOverflowException
            ? $"Windows dropped change notifications for {root} (buffer overflow). Changes may have been missed; run a manual scan of this folder."
            : $"Monitoring of {root} reported an error: {ex.Message}");
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), _time, ct).ConfigureAwait(false);
            try
            {
                await ProcessDueAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _lastError = ex.Message;
                Log(EventSeverity.Error, $"Monitoring scan failed: {ex.Message}");
            }
        }
    }

    /// <summary>Scans every path whose changes have settled. Exposed for deterministic tests.</summary>
    internal async Task ProcessDueAsync(CancellationToken ct)
    {
        var due = _debouncer.TakeSettled(64);
        if (due.Count == 0)
        {
            return;
        }

        var existing = due.Where(File.Exists).ToArray();
        if (existing.Length == 0)
        {
            return;
        }

        var report = await _runner.RunAsync(existing, null, ct).ConfigureAwait(false);
        if (report.Outcome == ScanOutcome.Aborted)
        {
            // Engine unavailable: keep the files queued instead of silently losing them.
            foreach (var p in existing)
            {
                _debouncer.Touch(p);
            }

            _lastError = string.Join("; ", report.Issues.Select(i => i.Message));
            Warn($"Scan engine unavailable; {existing.Length} changed file(s) are waiting: {_lastError}");
            return;
        }

        foreach (var r in report.Files)
        {
            if (r.Verdict == Verdict.Error && Retry(r.Path))
            {
                continue;
            }

            lock (_retries)
            {
                _retries.Remove(r.Path);
            }

            Interlocked.Increment(ref _scanned);
            if (r.Verdict is Verdict.Infected or Verdict.Suspicious)
            {
                Interlocked.Increment(ref _detections);
                Log(r.Verdict == Verdict.Infected ? EventSeverity.Threat : EventSeverity.Warning,
                    $"{r.Verdict} after change: {r.DetectionName}", r.Path, r.Sha256);
            }
            else if (r.Verdict is Verdict.Error or Verdict.Incomplete)
            {
                Log(EventSeverity.Warning, $"Changed file could not be fully checked ({r.Verdict}): {r.Message}", r.Path);
            }

            FileScanned?.Invoke(r);
        }
    }

    private bool Retry(string path)
    {
        lock (_retries)
        {
            var n = _retries.GetValueOrDefault(path) + 1;
            if (n > _options.MaxRetries)
            {
                return false;
            }

            _retries[path] = n;
        }

        _debouncer.Touch(path);
        return true;
    }

    private bool IsExcluded(string path)
    {
        var full = Path.GetFullPath(path);
        return _exclusions.Any(e => full.StartsWith(e, StringComparison.OrdinalIgnoreCase));
    }

    private void Warn(string message)
    {
        Log(EventSeverity.Warning, message);
        Warning?.Invoke(message);
    }

    private void Log(EventSeverity severity, string message, string? path = null, string? detail = null) =>
        _log?.Append(new SecurityEvent(_time.GetUtcNow(), severity, "monitor", message, path, detail));
}

/// <summary>
/// Lets other processes (CLI status, UI) see whether a monitor process is alive: the monitor
/// rewrites the file periodically; a missing or stale file means "not running".
/// </summary>
public static class MonitorHeartbeat
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    public static void Write(string file, IReadOnlyList<string> roots, TimeProvider? time = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        var stamp = (time ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds();
        AtomicFile.WriteAllBytes(file, System.Text.Encoding.UTF8.GetBytes($"{stamp}\n{string.Join('\n', roots)}"));
    }

    public static void Clear(string file)
    {
        try
        {
            File.Delete(file);
        }
        catch (IOException)
        {
        }
    }

    /// <returns>The watched roots if the heartbeat is fresh, otherwise null.</returns>
    public static IReadOnlyList<string>? ReadActive(string file, TimeProvider? time = null)
    {
        try
        {
            var lines = File.ReadAllLines(file);
            if (lines.Length == 0 || !long.TryParse(lines[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var stamp))
            {
                return null;
            }

            var age = (time ?? TimeProvider.System).GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(stamp);
            return age >= -TimeSpan.FromMinutes(1) && age <= Interval * 3 ? lines[1..] : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
