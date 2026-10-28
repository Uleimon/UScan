using System.Text.Json;
using System.Text.Json.Serialization;
using UScan.Core.Inventory;
using UScan.Core.Storage;

namespace UScan.Core.Monitoring;

public sealed record AutostartCheck(bool BaselineCreated, IReadOnlyList<InventoryChange> Changes, IReadOnlyList<string> Errors);

/// <summary>
/// Compares the current autostart/service/task inventory with the last stored baseline and
/// reports new or modified entries (a common way for malware to persist). Polling-based:
/// a change is noticed at the next check, not when it happens, and is never reverted automatically.
/// </summary>
public sealed class AutostartMonitor(InventoryCollector collector, string baselineFile, JsonLinesEventLog? log = null, TimeProvider? time = null)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = false,
    };

    public AutostartCheck Check()
    {
        var current = collector.Collect();
        var previous = Load();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(baselineFile))!);
        AtomicFile.WriteAllBytes(baselineFile, JsonSerializer.SerializeToUtf8Bytes(current, Json));
        if (previous is null)
        {
            Log(EventSeverity.Info, $"Autostart baseline created with {current.Entries.Count} entries.", null);
            return new AutostartCheck(true, [], current.Errors);
        }

        var changes = InventoryDiff.Compare(previous, current);
        foreach (var c in changes)
        {
            var sev = c.ChangeType == "Removed" || c.Entry.Signature?.IsTrusted == true ? EventSeverity.Info : EventSeverity.Warning;
            Log(sev, $"Autostart entry {c.ChangeType.ToLowerInvariant()}: {c.Entry.Kind} '{c.Entry.Name}' ({c.Entry.Signature?.Status.ToString() ?? "not checked"})", c.Entry.ImagePath ?? c.Entry.Location);
        }

        return new AutostartCheck(false, changes, current.Errors);
    }

    private InventorySnapshot? Load()
    {
        if (!File.Exists(baselineFile))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<InventorySnapshot>(File.ReadAllBytes(baselineFile), Json);
        }
        catch (JsonException ex)
        {
            Log(EventSeverity.Warning, $"Autostart baseline unreadable, recreated: {ex.Message}", baselineFile);
            return null;
        }
    }

    private void Log(EventSeverity s, string message, string? path) =>
        log?.Append(new SecurityEvent((time ?? TimeProvider.System).GetUtcNow(), s, "autostart", message, path));
}
