using System.Security.Cryptography;
using System.Text.Json;
using UScan.Core.Engines;
using UScan.Core.Hashing;
using UScan.Core.Model;
using UScan.Core.Storage;

namespace UScan.Core.Quarantine;

public enum QuarantineState
{
    /// <summary>Encrypted copy stored and the original removed.</summary>
    Isolated,

    /// <summary>Encrypted copy stored but the original could not be removed (in use, access denied, or changed). It is still active on disk.</summary>
    OriginalNotRemoved,
}

public sealed record QuarantineItem(
    Guid Id,
    string OriginalPath,
    string Sha256,
    long SizeBytes,
    string DetectionName,
    string EngineId,
    DateTimeOffset QuarantinedAt,
    QuarantineState State,
    string? StateDetail,
    string KeyBase64,
    string NonceBase64);

public sealed record QuarantineResult(bool Success, QuarantineItem? Item, string Message);

public sealed record RestoreResult(bool Success, string Message, Verdict? RescanVerdict = null, string? RestoredTo = null);

/// <summary>
/// Isolates detected files. Safety properties (each covered by tests):
/// <list type="bullet">
/// <item>Symlinks/reparse points are never quarantined or followed.</item>
/// <item>Files in protected locations require explicit administrator confirmation.</item>
/// <item>If the file changed since the scan (hash mismatch) nothing is done.</item>
/// <item>The original is only deleted if a byte-identical, verified copy is in quarantine.
///       The original is first renamed in its own directory and re-hashed, so a path swapped
///       between the checks can never cause a different file to be deleted.</item>
/// <item>Restore decrypts with authentication, re-scans, refuses existing targets and reparse
///       points in the target path, and writes via temp file + rename without overwrite.</item>
/// </list>
/// </summary>
public sealed class QuarantineStore
{
    private readonly string _dir;
    private readonly IFileProtectionPolicy _policy;
    private readonly TimeProvider _time;
    private readonly JsonLinesEventLog? _log;

    public QuarantineStore(string directory, IFileProtectionPolicy policy, JsonLinesEventLog? log = null, TimeProvider? time = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(policy);
        _dir = Directory.CreateDirectory(directory).FullName;
        _policy = policy;
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    public async Task<QuarantineResult> QuarantineAsync(
        string path,
        string detectionName,
        string engineId,
        string? expectedSha256,
        bool adminConfirmedProtectedFile = false,
        CancellationToken ct = default)
    {
        var full = Path.GetFullPath(path);
        var info = new FileInfo(full);
        if (!info.Exists)
        {
            return Fail("File does not exist.");
        }

        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return Fail("Symbolic links and reparse points are not quarantined.");
        }

        if (IsInside(full, _dir))
        {
            return Fail("File is already inside the quarantine directory.");
        }

        if (_policy.GetProtectionReason(full) is { } reason && !adminConfirmedProtectedFile)
        {
            return Fail($"Protected file: {reason} An administrator must confirm this action explicitly.");
        }

        var id = Guid.NewGuid();
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var payload = PayloadPath(id);
        var tmp = payload + ".tmp";
        QuarantineCrypto.SealResult sealedResult;

        try
        {
            // FileShare.Read: nobody can modify the file while it is being copied.
            await using (var src = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var dst = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                sealedResult = await QuarantineCrypto.SealAsync(src, dst, id, key, nonce, ct).ConfigureAwait(false);
                await dst.FlushAsync(ct).ConfigureAwait(false);
                dst.Flush(flushToDisk: true);
            }

            if (expectedSha256 is not null && !expectedSha256.Equals(sealedResult.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tmp);
                return Fail("File changed since it was scanned (SHA-256 differs). Scan it again before quarantining.");
            }

            // Verify what was written before touching the original.
            await using (var check = new FileStream(tmp, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous))
            {
                var verified = await QuarantineCrypto.OpenAsync(check, Stream.Null, id, key, nonce, ct).ConfigureAwait(false);
                if (verified.Sha256 != sealedResult.Sha256)
                {
                    throw new QuarantineIntegrityException("Read-back verification failed.");
                }
            }

            File.Move(tmp, payload);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or QuarantineIntegrityException)
        {
            TryDelete(tmp);
            return Fail($"Could not create quarantine copy: {ex.Message}");
        }

        var (state, detail) = RemoveOriginal(full, sealedResult.Sha256);
        var item = new QuarantineItem(id, full, sealedResult.Sha256, sealedResult.Length, detectionName, engineId,
            _time.GetUtcNow(), state, detail, Convert.ToBase64String(key), Convert.ToBase64String(nonce));
        AtomicFile.WriteAllBytes(MetaPath(id), JsonSerializer.SerializeToUtf8Bytes(item, JsonLinesEventLog.Json));

        var message = state == QuarantineState.Isolated
            ? "File moved to quarantine."
            : $"Copy stored in quarantine, but the original is STILL PRESENT: {detail}";
        _log?.Append(new SecurityEvent(_time.GetUtcNow(), state == QuarantineState.Isolated ? EventSeverity.Info : EventSeverity.Warning,
            "quarantine", message, full, $"{detectionName} sha256={sealedResult.Sha256} id={id}"));
        return new QuarantineResult(state == QuarantineState.Isolated, item, message);

        QuarantineResult Fail(string msg)
        {
            _log?.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Warning, "quarantine", $"Quarantine refused: {msg}", full));
            return new QuarantineResult(false, null, msg);
        }
    }

    public IReadOnlyList<QuarantineItem> List()
    {
        var items = new List<QuarantineItem>();
        foreach (var meta in Directory.EnumerateFiles(_dir, "*.json"))
        {
            try
            {
                if (JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllBytes(meta), JsonLinesEventLog.Json) is { } item)
                {
                    items.Add(item);
                }
            }
            catch (JsonException)
            {
                // A damaged metadata file is reported through VerifyAsync on its payload, not listed.
            }
        }

        return items.OrderByDescending(i => i.QuarantinedAt).ToArray();
    }

    /// <summary>Decrypts in memory-free streaming mode and checks authentication tags and hash.</summary>
    public async Task<bool> VerifyAsync(Guid id, CancellationToken ct = default)
    {
        var item = Get(id);
        if (item is null)
        {
            return false;
        }

        try
        {
            await using var input = File.OpenRead(PayloadPath(id));
            var r = await QuarantineCrypto.OpenAsync(input, Stream.Null, id, Convert.FromBase64String(item.KeyBase64), Convert.FromBase64String(item.NonceBase64), ct).ConfigureAwait(false);
            return r.Sha256 == item.Sha256;
        }
        catch (Exception ex) when (ex is QuarantineIntegrityException or IOException)
        {
            return false;
        }
    }

    /// <param name="id">Quarantine item.</param>
    /// <param name="engine">Used to re-scan the content before it is written back.</param>
    /// <param name="targetPath">Defaults to the original path.</param>
    /// <param name="confirmedDespiteDetection">Must be true to restore content the engine still detects.</param>
    /// <param name="ct">Cancellation.</param>
    public async Task<RestoreResult> RestoreAsync(Guid id, IScanEngine engine, string? targetPath = null, bool confirmedDespiteDetection = false, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(engine);
        var item = Get(id);
        if (item is null)
        {
            return new RestoreResult(false, "Unknown quarantine item.");
        }

        var target = Path.GetFullPath(targetPath ?? item.OriginalPath);
        var parent = Path.GetDirectoryName(target);
        if (parent is null || !Directory.Exists(parent))
        {
            return new RestoreResult(false, "Target directory does not exist.");
        }

        if (File.Exists(target) || Directory.Exists(target) || IsLink(target))
        {
            return new RestoreResult(false, "Target already exists; it will not be overwritten.");
        }

        if (FindReparsePointInPath(parent) is { } link)
        {
            return new RestoreResult(false, $"Target path contains a link or junction ('{link}'); refusing to restore through it.");
        }

        var key = Convert.FromBase64String(item.KeyBase64);
        var nonce = Convert.FromBase64String(item.NonceBase64);

        // Decrypt + verify into a temp file next to the target (same volume → atomic rename).
        var tmp = Path.Combine(parent, $".uscan-restore-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var input = File.OpenRead(PayloadPath(id)))
            await using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                var r = await QuarantineCrypto.OpenAsync(input, output, id, key, nonce, ct).ConfigureAwait(false);
                if (r.Sha256 != item.Sha256)
                {
                    throw new QuarantineIntegrityException("Decrypted content does not match the recorded SHA-256.");
                }

                output.Flush(flushToDisk: true);
            }

            EngineResult rescan;
            await using (var check = new FileStream(tmp, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                rescan = await engine.ScanAsync(check, ct).ConfigureAwait(false);
            }

            if (rescan.Verdict != Verdict.Clean && !confirmedDespiteDetection)
            {
                TryDelete(tmp);
                return new RestoreResult(false,
                    $"Re-scan result is '{rescan.Verdict}' ({rescan.DetectionName ?? rescan.Detail}). Restore requires explicit confirmation.", rescan.Verdict);
            }

            File.Move(tmp, target, overwrite: false);
            File.Delete(PayloadPath(id));
            File.Delete(MetaPath(id));
            _log?.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Warning, "quarantine",
                $"Restored from quarantine (re-scan: {rescan.Verdict}).", target, $"id={id} sha256={item.Sha256}"));
            return new RestoreResult(true, "Restored.", rescan.Verdict, target);
        }
        catch (QuarantineIntegrityException ex)
        {
            TryDelete(tmp);
            _log?.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Error, "quarantine", $"Integrity check failed: {ex.Message}", item.OriginalPath, $"id={id}"));
            return new RestoreResult(false, $"Integrity check failed: {ex.Message}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tmp);
            return new RestoreResult(false, $"Restore failed: {ex.Message}");
        }
    }

    /// <summary>Permanently removes an item. Callers must have obtained explicit user confirmation.</summary>
    public bool DeletePermanently(Guid id, bool userConfirmed)
    {
        if (!userConfirmed || Get(id) is not { } item)
        {
            return false;
        }

        File.Delete(PayloadPath(id));
        File.Delete(MetaPath(id));
        _log?.Append(new SecurityEvent(_time.GetUtcNow(), EventSeverity.Info, "quarantine", "Quarantine item deleted permanently.", item.OriginalPath, $"id={id}"));
        return true;
    }

    public QuarantineItem? Get(Guid id)
    {
        try
        {
            return JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllBytes(MetaPath(id)), JsonLinesEventLog.Json);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return null;
        }
    }

    private (QuarantineState, string?) RemoveOriginal(string full, string expectedSha)
    {
        var dir = Path.GetDirectoryName(full)!;
        var pending = Path.Combine(dir, $".uscan-pending-{Guid.NewGuid():N}");
        try
        {
            // Rename acts on the directory entry and never follows a final symlink.
            File.Move(full, pending);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (QuarantineState.OriginalNotRemoved, ex.Message);
        }

        try
        {
            var pendingInfo = new FileInfo(pending);
            string actual;
            if (pendingInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                actual = "(link)";
            }
            else
            {
                using var fs = new FileStream(pending, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var h = new HashingReadStream(fs);
                actual = h.CompleteAsync(CancellationToken.None).GetAwaiter().GetResult();
            }

            if (actual != expectedSha)
            {
                File.Move(pending, full);
                return (QuarantineState.OriginalNotRemoved, "The file at this path changed during quarantine; it was left in place.");
            }

            File.Delete(pending);
            return (QuarantineState.Isolated, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try
            {
                if (File.Exists(pending) && !File.Exists(full))
                {
                    File.Move(pending, full);
                }
            }
            catch (IOException)
            {
            }

            return (QuarantineState.OriginalNotRemoved, ex.Message);
        }
    }

    private string PayloadPath(Guid id) => Path.Combine(_dir, $"{id:N}.bin");
    private string MetaPath(Guid id) => Path.Combine(_dir, $"{id:N}.json");

    private static bool IsLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>Returns the first ancestor (inclusive) that is a symlink/junction, or null.</summary>
    internal static string? FindReparsePointInPath(string directory)
    {
        for (var d = new DirectoryInfo(directory); d is not null; d = d.Parent)
        {
            if (d.Exists && d.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return d.FullName;
            }
        }

        return null;
    }

    private static bool IsInside(string path, string dir)
    {
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var d = Path.TrimEndingDirectorySeparator(dir) + Path.DirectorySeparatorChar;
        return path.StartsWith(d, cmp);
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
