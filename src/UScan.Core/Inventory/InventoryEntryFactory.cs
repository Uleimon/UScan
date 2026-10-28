using System.Security.Cryptography;

namespace UScan.Core.Inventory;

/// <summary>Turns a raw persistence record into an <see cref="InventoryEntry"/> with hash, signature and factual observations.</summary>
public sealed class InventoryEntryFactory
{
    private static readonly string[] UserWritableMarkers =
    [
        @"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\AppData\Local\", @"\Downloads\", @"\Users\Public\", @"\Windows\Temp\", @"\ProgramData\",
    ];

    private readonly CommandLineResolver _resolver;
    private readonly ISignatureVerifier _signatures;
    private readonly long _maxHashBytes;

    public InventoryEntryFactory(CommandLineResolver resolver, ISignatureVerifier signatures, long maxHashBytes = 512L * 1024 * 1024)
    {
        _resolver = resolver;
        _signatures = signatures;
        _maxHashBytes = maxHashBytes;
    }

    public InventoryEntry Create(InventoryKind kind, string location, string name, string? command, IEnumerable<string>? extraObservations = null)
    {
        var resolved = _resolver.Resolve(command);
        var notes = new List<string>(resolved.Observations);
        if (extraObservations is not null)
        {
            notes.AddRange(extraObservations);
        }

        // For proxy/script hosts the interesting file is the target, not rundll32/powershell itself.
        var file = resolved.Target ?? resolved.Executable;
        bool? exists = null;
        string? sha = null;
        SignatureInfo? sig = null;

        if (!string.IsNullOrEmpty(file) && Path.IsPathFullyQualified(file))
        {
            exists = File.Exists(file);
            if (exists == true)
            {
                sha = TryHash(file, notes);
                sig = _signatures.Verify(file);
                switch (sig.Status)
                {
                    case SignatureStatus.NotSigned:
                        notes.Add("File is not digitally signed.");
                        break;
                    case SignatureStatus.Invalid:
                        notes.Add("Digital signature is INVALID (file modified after signing).");
                        break;
                    case SignatureStatus.Untrusted:
                        notes.Add($"Signature is not trusted: {sig.Detail}");
                        break;
                }
            }
            else
            {
                notes.Add("Referenced file does not exist (stale entry or removed program).");
            }

            var normalized = file.Replace('/', '\\');
            if (UserWritableMarkers.Any(m => normalized.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                notes.Add("Runs from a user-writable location.");
            }
        }
        else if (!string.IsNullOrEmpty(file))
        {
            notes.Add("Executable path could not be resolved to a full path.");
        }

        return new InventoryEntry(kind, location, name, command, file, exists, sha, sig, notes);
    }

    private string? TryHash(string file, List<string> notes)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length > _maxHashBytes)
            {
                notes.Add("File too large to hash.");
                return null;
            }

            return Convert.ToHexStringLower(SHA256.HashData(fs));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            notes.Add($"File could not be read: {ex.Message}");
            return null;
        }
    }
}

/// <summary>Collects from all sources; a failing source is reported, never fatal.</summary>
public sealed class InventoryCollector(IEnumerable<IInventorySource> sources, TimeProvider? time = null)
{
    public InventorySnapshot Collect()
    {
        var errors = new List<string>();
        var entries = new List<InventoryEntry>();
        foreach (var source in sources)
        {
            try
            {
                entries.AddRange(source.Collect(errors));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException or System.Runtime.InteropServices.COMException)
            {
                errors.Add($"{source.Name}: {ex.Message}");
            }
        }

        return new InventorySnapshot((time ?? TimeProvider.System).GetUtcNow(), entries, errors);
    }
}

public sealed record InventoryChange(string ChangeType, InventoryEntry Entry, InventoryEntry? Previous);

/// <summary>Compares two snapshots to detect new/changed/removed persistence (used for monitoring autostart changes).</summary>
public static class InventoryDiff
{
    public static IReadOnlyList<InventoryChange> Compare(InventorySnapshot before, InventorySnapshot after)
    {
        static string Key(InventoryEntry e) => $"{e.Kind}|{e.Location}|{e.Name}";
        var old = before.Entries.GroupBy(Key).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var now = after.Entries.GroupBy(Key).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var changes = new List<InventoryChange>();
        foreach (var (k, e) in now)
        {
            if (!old.TryGetValue(k, out var prev))
            {
                changes.Add(new InventoryChange("Added", e, null));
            }
            else if (!string.Equals(prev.Command, e.Command, StringComparison.Ordinal) || !string.Equals(prev.Sha256, e.Sha256, StringComparison.Ordinal))
            {
                changes.Add(new InventoryChange("Modified", e, prev));
            }
        }

        changes.AddRange(old.Where(kv => !now.ContainsKey(kv.Key)).Select(kv => new InventoryChange("Removed", kv.Value, null)));
        return changes;
    }
}
