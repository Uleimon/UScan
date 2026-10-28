using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using UScan.Core.Engines;
using UScan.Core.Hashing;
using UScan.Core.Model;

namespace UScan.Core.Scanning;

public sealed class ScanOptions
{
    public int MaxDegreeOfParallelism { get; init; } = 2;

    /// <summary>Directory nesting limit, protects against pathological trees.</summary>
    public int MaxDirectoryDepth { get; init; } = 64;

    /// <summary>Must match the engine's archive limits so that partial archive scans are reported as incomplete.</summary>
    public ArchiveLimits ArchiveLimits { get; init; } = ArchiveLimits.Default;

    /// <summary>Optional heuristic analyzers, run on files the engine reported as clean. Results are at most "suspicious".</summary>
    public IReadOnlyList<Heuristics.IHeuristicAnalyzer> Heuristics { get; init; } = [];

    /// <summary>
    /// Optional independent engine consulted for every infected or suspicious file (scan mode "second opinion").
    /// A signature hit from it upgrades a heuristic "suspicious" to "infected"; it never downgrades a detection.
    /// </summary>
    public Engines.IFileScanEngine? SecondOpinion { get; init; }

    /// <summary>
    /// How often, and how far apart, the engine is pinged after a lost connection before the scan
    /// is aborted. A single dropped connection (clamd restarting, a paused console window) then
    /// costs one retry instead of the whole scan.
    /// </summary>
    public int EngineRecoveryAttempts { get; init; } = 6;

    public TimeSpan EngineRecoveryDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Test seam for simulating I/O failures. Production code uses <see cref="OpenForScan"/>.</summary>
    internal Func<string, Stream>? OpenFile { get; init; }

    /// <summary>
    /// Opens a file read-only while allowing other processes to keep using it. UScan never
    /// takes a write handle during scanning.
    /// </summary>
    public static Stream OpenForScan(string path) => new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete,
        bufferSize: 81920,
        FileOptions.Asynchronous | FileOptions.SequentialScan);
}

/// <summary>
/// Enumerates the requested roots and sends every regular file to one engine.
/// Symbolic links and other reparse points are never followed (prevents loops and
/// scans being redirected to unintended locations) and are reported as skipped.
/// </summary>
public sealed class ScanRunner
{
    private readonly IScanEngine _engine;
    private readonly ScanOptions _options;
    private readonly TimeProvider _time;

    public ScanRunner(IScanEngine engine, ScanOptions? options = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        _engine = engine;
        _options = options ?? new ScanOptions();
        _time = time ?? TimeProvider.System;
        if (_options.MaxDegreeOfParallelism < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxDegreeOfParallelism must be at least 1.");
        }
    }

    public async Task<ScanReport> RunAsync(
        IReadOnlyList<string> roots,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(roots);
        var started = _time.GetUtcNow();
        var fullRoots = roots.Select(Path.GetFullPath).ToArray();
        var results = new ConcurrentBag<FileScanResult>();
        var issues = new ConcurrentBag<ScanIssue>();
        var counters = new Counters();

        EngineInfo engineInfo;
        try
        {
            engineInfo = await _engine.GetInfoAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (EngineUnavailableException ex)
        {
            issues.Add(new ScanIssue("(engine)", ex.Message));
            return Finish(ScanOutcome.Aborted, null);
        }

        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var outcome = ScanOutcome.Completed;
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(1024) { SingleWriter = true });

        var producer = Task.Run(() => Enumerate(fullRoots, channel.Writer, results, issues, counters, progress, abort.Token), CancellationToken.None);

        try
        {
            await Parallel.ForEachAsync(
                channel.Reader.ReadAllAsync(abort.Token),
                new ParallelOptions { MaxDegreeOfParallelism = _options.MaxDegreeOfParallelism, CancellationToken = abort.Token },
                async (path, ct) =>
                {
                    var r = await ScanFileAsync(path, ct).ConfigureAwait(false);
                    results.Add(r);
                    counters.Complete(r);
                    progress?.Report(counters.Snapshot(path));
                }).ConfigureAwait(false);
        }
        catch (EngineUnavailableException ex)
        {
            outcome = ScanOutcome.Aborted;
            issues.Add(new ScanIssue("(engine)", ex.Message));
            await abort.CancelAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = ScanOutcome.Cancelled;
        }

        try
        {
            await producer.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (abort.IsCancellationRequested)
        {
        }

        progress?.Report(counters.Snapshot(null));
        return Finish(outcome, engineInfo);

        ScanReport Finish(ScanOutcome o, EngineInfo? info) => new(
            Guid.NewGuid(),
            started,
            _time.GetUtcNow(),
            o,
            fullRoots,
            info,
            counters.Discovered,
            results.OrderBy(r => r.Path, StringComparer.Ordinal).ToArray(),
            issues.OrderBy(i => i.Path, StringComparer.Ordinal).ToArray());
    }

    private async Task Enumerate(
        string[] roots,
        ChannelWriter<string> writer,
        ConcurrentBag<FileScanResult> results,
        ConcurrentBag<ScanIssue> issues,
        Counters counters,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        try
        {
            foreach (var root in roots)
            {
                FileSystemInfo info = Directory.Exists(root) ? new DirectoryInfo(root) : new FileInfo(root);
                if (!info.Exists)
                {
                    issues.Add(new ScanIssue(root, "Path does not exist."));
                    continue;
                }

                var stack = new Stack<(FileSystemInfo Item, int Depth)>();
                stack.Push((info, 0));
                while (stack.Count > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    var (item, depth) = stack.Pop();

                    if (item.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        counters.Discover();
                        var skipped = Skipped(item.FullName, null, SkipReason.ReparsePointOrSymlink);
                        results.Add(skipped);
                        counters.Complete(skipped);
                        continue;
                    }

                    if (item is DirectoryInfo dir)
                    {
                        if (depth >= _options.MaxDirectoryDepth)
                        {
                            issues.Add(new ScanIssue(dir.FullName, $"Directory depth limit ({_options.MaxDirectoryDepth}) reached; contents not scanned."));
                            continue;
                        }

                        try
                        {
                            // Materialise before pushing so an access error is attributed to this directory only.
                            var children = dir.EnumerateFileSystemInfos("*", new EnumerationOptions
                            {
                                RecurseSubdirectories = false,
                                IgnoreInaccessible = false,
                                AttributesToSkip = 0,
                                ReturnSpecialDirectories = false,
                            }).ToList();
                            for (var i = children.Count - 1; i >= 0; i--)
                            {
                                stack.Push((children[i], depth + 1));
                            }
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                        {
                            issues.Add(new ScanIssue(dir.FullName, $"Directory could not be read: {ex.Message}"));
                        }

                        continue;
                    }

                    counters.Discover();
                    await writer.WriteAsync(item.FullName, ct).ConfigureAwait(false);
                    if (counters.Discovered % 256 == 0)
                    {
                        progress?.Report(counters.Snapshot(null));
                    }
                }
            }

            counters.EnumerationComplete = true;
            writer.TryComplete();
        }
        catch (Exception ex)
        {
            writer.TryComplete(ex is OperationCanceledException ? null : ex);
            if (ex is not OperationCanceledException)
            {
                throw;
            }
        }
    }

    private async Task<FileScanResult> ScanFileAsync(string path, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        long? size = null;
        try
        {
            var fi = new FileInfo(path);
            size = fi.Length;
            if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return Skipped(path, size, SkipReason.ReparsePointOrSymlink);
            }

            if (size > _engine.MaxStreamBytes)
            {
                return Skipped(path, size, SkipReason.TooLarge);
            }

            (EngineResult Result, long Bytes, string Sha) scanned;
            try
            {
                scanned = await ScanContentAsync(path, ct).ConfigureAwait(false);
            }
            catch (EngineUnavailableException first)
            {
                // Throws (and so aborts the scan) only if the engine stays unreachable.
                await WaitForEngineAsync(first, ct).ConfigureAwait(false);
                try
                {
                    scanned = await ScanContentAsync(path, ct).ConfigureAwait(false);
                }
                catch (EngineUnavailableException again)
                {
                    if (!await IsReachableAsync(ct).ConfigureAwait(false))
                    {
                        throw;
                    }

                    // The engine is up but drops this particular file: report the file, keep scanning.
                    return new FileScanResult(path, size, null, Verdict.Error, SkipReason.None, [],
                        $"Engine dropped the connection for this file twice: {again.Message}", sw.Elapsed);
                }
            }

            var (engineResult, bytesRead, sha) = scanned;
            if (engineResult.Verdict == Verdict.Clean)
            {
                engineResult = CheckArchiveCoverage(path, engineResult);
            }

            var results = new List<EngineResult> { engineResult };
            if (engineResult.Verdict == Verdict.Clean && RunHeuristics(path, bytesRead) is { } heuristic)
            {
                results.Add(heuristic);
                engineResult = heuristic;
            }

            if (_options.SecondOpinion is { } second && engineResult.Verdict is Verdict.Infected or Verdict.Suspicious)
            {
                var opinion = await second.ScanFileAsync(path, ct).ConfigureAwait(false);
                results.Add(opinion);
                if (engineResult.Verdict == Verdict.Suspicious && opinion.Verdict == Verdict.Infected)
                {
                    engineResult = opinion;
                }
            }

            return new FileScanResult(path, bytesRead, sha, engineResult.Verdict,
                engineResult.Verdict == Verdict.Skipped ? SkipReason.TooLarge : SkipReason.None,
                results, engineResult.Verdict is Verdict.Error or Verdict.Incomplete or Verdict.Suspicious ? engineResult.Detail : null, sw.Elapsed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileScanResult(path, size, null, Verdict.Error, SkipReason.None, [], ex.Message, sw.Elapsed);
        }
    }

    private EngineResult? RunHeuristics(string path, long size)
    {
        if (_options.Heuristics.Count == 0 || size > 64L * 1024 * 1024)
        {
            return null;
        }

        Span<byte> header = stackalloc byte[8];
        int headerLength;
        using (var probe = (_options.OpenFile ?? ScanOptions.OpenForScan)(path))
        {
            headerLength = probe.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
        }

        foreach (var analyzer in _options.Heuristics)
        {
            if (!analyzer.CanAnalyze(path, header[..headerLength]))
            {
                continue;
            }

            using var stream = (_options.OpenFile ?? ScanOptions.OpenForScan)(path);
            var r = analyzer.Analyze(path, stream);
            if (r.Suspicious)
            {
                return new EngineResult(Verdict.Suspicious, "uscan-heuristic", $"UScan.Heuristic.Score{r.Score}", r.Explain());
            }
        }

        return null;
    }

    private async Task<(EngineResult Result, long Bytes, string Sha)> ScanContentAsync(string path, CancellationToken ct)
    {
        await using var hashing = new HashingReadStream((_options.OpenFile ?? ScanOptions.OpenForScan)(path));
        var result = await _engine.ScanAsync(hashing, ct).ConfigureAwait(false);
        var sha = await hashing.CompleteAsync(ct).ConfigureAwait(false);
        return (result, hashing.BytesRead, sha);
    }

    private async Task WaitForEngineAsync(EngineUnavailableException cause, CancellationToken ct)
    {
        for (var i = 0; i < _options.EngineRecoveryAttempts; i++)
        {
            await Task.Delay(_options.EngineRecoveryDelay, _time, ct).ConfigureAwait(false);
            if (await IsReachableAsync(ct).ConfigureAwait(false))
            {
                return;
            }
        }

        throw new EngineUnavailableException(
            $"{cause.Message} (still unreachable after {_options.EngineRecoveryAttempts} attempts, {_options.EngineRecoveryDelay.TotalSeconds:F0} s apart)", cause);
    }

    private async Task<bool> IsReachableAsync(CancellationToken ct)
    {
        try
        {
            await _engine.GetInfoAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (EngineUnavailableException)
        {
            return false;
        }
    }

    /// <summary>Downgrades "clean" to "incomplete" when the engine cannot have seen the whole archive.</summary>
    private EngineResult CheckArchiveCoverage(string path, EngineResult clean)
    {
        using var stream = (_options.OpenFile ?? ScanOptions.OpenForScan)(path);
        Span<byte> header = stackalloc byte[4];
        if (stream.ReadAtLeast(header, 4, throwOnEndOfStream: false) < 4 || !ZipLimitInspector.LooksLikeZip(header))
        {
            return clean;
        }

        stream.Position = 0;
        var gap = ZipLimitInspector.FindCoverageGap(stream, _options.ArchiveLimits);
        return gap is null ? clean : clean with { Verdict = Verdict.Incomplete, Detail = gap };
    }

    private static FileScanResult Skipped(string path, long? size, SkipReason reason) =>
        new(path, size, null, Verdict.Skipped, reason, [], null, TimeSpan.Zero);

    private sealed class Counters
    {
        private long _discovered;
        private long _completed;
        private long _skipped;
        private long _errors;
        private long _bytes;

        public volatile bool EnumerationComplete;

        public long Discovered => Interlocked.Read(ref _discovered);

        public void Discover() => Interlocked.Increment(ref _discovered);

        public void Complete(FileScanResult r)
        {
            Interlocked.Increment(ref _completed);
            if (r.Verdict == Verdict.Skipped)
            {
                Interlocked.Increment(ref _skipped);
            }
            else if (r.Verdict == Verdict.Error)
            {
                Interlocked.Increment(ref _errors);
            }
            else if (r.SizeBytes is { } b)
            {
                Interlocked.Add(ref _bytes, b);
            }
        }

        public ScanProgress Snapshot(string? current) => new(
            Interlocked.Read(ref _discovered),
            Interlocked.Read(ref _completed),
            Interlocked.Read(ref _skipped),
            Interlocked.Read(ref _errors),
            Interlocked.Read(ref _bytes),
            EnumerationComplete,
            current);
    }
}
