using System.Text.Json;
using System.Text.Json.Serialization;
using UScan.Core.Storage;

namespace UScan.Core.App;

/// <summary>User settings, stored as settings.json in the data folder. Missing values fall back to the defaults below.</summary>
public sealed record UScanSettings
{
    public string ClamdHost { get; init; } = "127.0.0.1";
    public int ClamdPort { get; init; } = 3310;

    /// <summary>Must not exceed StreamMaxLength in clamd.conf.</summary>
    public long MaxStreamMb { get; init; } = 100;

    /// <summary>Must match MaxFileSize, MaxScanSize and MaxFiles in clamd.conf (used to detect silently truncated archive scans).</summary>
    public long ArchiveMaxFileMb { get; init; } = 100;
    public long ArchiveMaxScanMb { get; init; } = 400;
    public int ArchiveMaxFiles { get; init; } = 10_000;

    public int MaxSignatureAgeDays { get; init; } = 3;
    public int Parallelism { get; init; } = 2;
    public bool HeuristicsEnabled { get; init; } = true;

    /// <summary>Ask Microsoft Defender for a second opinion on detections (Windows only, local, no upload).</summary>
    public bool DefenderSecondOpinion { get; init; } = true;

    public string? FreshclamPath { get; init; }
    public string? FreshclamConfig { get; init; }

    /// <summary>Folders re-scanned after changes when monitoring runs. Empty = Downloads and Desktop of the current user.</summary>
    public IReadOnlyList<string> WatchFolders { get; init; } = [];

    public int AutostartCheckMinutes { get; init; } = 15;

    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>Loads settings. A broken file is reported via <paramref name="error"/> and defaults are used; it is never overwritten silently.</summary>
    public static UScanSettings Load(string path, out string? error)
    {
        error = null;
        if (!File.Exists(path))
        {
            return new UScanSettings();
        }

        try
        {
            var s = JsonSerializer.Deserialize<UScanSettings>(File.ReadAllBytes(path), Json) ?? new UScanSettings();
            error = s.Validate();
            return error is null ? s : new UScanSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            error = $"settings.json could not be read ({ex.Message}); defaults are used.";
            return new UScanSettings();
        }
    }

    public void Save(string path)
    {
        if (Validate() is { } error)
        {
            throw new ArgumentException(error);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        AtomicFile.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(this, Json));
    }

    public string? Validate()
    {
        if (ClamdPort is < 1 or > 65535)
        {
            return "clamdPort must be between 1 and 65535.";
        }

        if (MaxStreamMb < 1 || ArchiveMaxFileMb < 1 || ArchiveMaxScanMb < 1 || ArchiveMaxFiles < 1)
        {
            return "Size and file limits must be positive.";
        }

        if (MaxSignatureAgeDays is < 1 or > 30)
        {
            return "maxSignatureAgeDays must be between 1 and 30.";
        }

        if (Parallelism is < 1 or > 16)
        {
            return "parallelism must be between 1 and 16.";
        }

        return AutostartCheckMinutes is < 1 or > 1440 ? "autostartCheckMinutes must be between 1 and 1440." : null;
    }
}
