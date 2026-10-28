using UScan.Core.Inventory;

namespace UScan.Core.Scanning;

public enum ScanMode
{
    /// <summary>Locations where downloaded or dropped malware typically lands, plus all autostart targets.</summary>
    Quick,

    /// <summary>Every ready fixed drive.</summary>
    Full,

    /// <summary>Only the executables referenced by autostart entries, services and scheduled tasks.</summary>
    Autostart,

    /// <summary>User-chosen files and folders.</summary>
    Custom,
}

/// <param name="Mode">Requested scan mode.</param>
/// <param name="Roots">Existing files/folders to scan.</param>
/// <param name="MaxDirectoryDepth">Depth limit for this mode (quick scans do not descend into deep trees).</param>
/// <param name="Notes">What is covered and what is not, shown to the user before the scan.</param>
public sealed record ScanPlan(ScanMode Mode, IReadOnlyList<string> Roots, int MaxDirectoryDepth, IReadOnlyList<string> Notes);

/// <summary>Abstraction of the few environment facts the planner needs, so plans are testable.</summary>
public interface IScanEnvironment
{
    string? GetFolder(Environment.SpecialFolder folder);
    string? TempPath { get; }
    IEnumerable<string> FixedDriveRoots();
    bool Exists(string path);
}

public sealed class SystemScanEnvironment : IScanEnvironment
{
    public string? GetFolder(Environment.SpecialFolder folder) => Environment.GetFolderPath(folder) is { Length: > 0 } p ? p : null;

    public string? TempPath => Path.GetTempPath();

    public IEnumerable<string> FixedDriveRoots() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName);

    public bool Exists(string path) => File.Exists(path) || Directory.Exists(path);
}

public sealed class ScanPlanner(IScanEnvironment? environment = null)
{
    private readonly IScanEnvironment _env = environment ?? new SystemScanEnvironment();

    /// <param name="mode">Requested scan mode.</param>
    /// <param name="inventory">Required for Quick and Autostart; without it these modes say so in their notes.</param>
    /// <param name="customPaths">Used for Custom only.</param>
    public ScanPlan Create(ScanMode mode, InventorySnapshot? inventory = null, IReadOnlyList<string>? customPaths = null)
    {
        var notes = new List<string>();
        var roots = new List<string>();
        int depth;
        switch (mode)
        {
            case ScanMode.Quick:
                depth = 4;
                foreach (var f in new[]
                {
                    Environment.SpecialFolder.DesktopDirectory,
                    Environment.SpecialFolder.Startup,
                    Environment.SpecialFolder.CommonStartup,
                    Environment.SpecialFolder.ApplicationData,
                })
                {
                    Add(_env.GetFolder(f));
                }

                if (_env.GetFolder(Environment.SpecialFolder.UserProfile) is { } profile)
                {
                    Add(Path.Combine(profile, "Downloads"));
                }

                Add(_env.TempPath);
                AddInventoryTargets();
                notes.Add($"Quick scan: desktop, downloads, temp, roaming app data and startup folders up to depth {depth}, plus all autostart targets. Other locations are not checked; use a full scan for that.");
                break;

            case ScanMode.Full:
                depth = 64;
                foreach (var d in _env.FixedDriveRoots())
                {
                    Add(d);
                }

                notes.Add("Full scan of all fixed drives. Removable/network drives, files above the engine size limit and files Windows denies access to are reported as skipped, not as clean.");
                break;

            case ScanMode.Autostart:
                depth = 1;
                AddInventoryTargets();
                notes.Add("Only the program files referenced by autostart entries, services and scheduled tasks are scanned.");
                break;

            case ScanMode.Custom:
                depth = 64;
                foreach (var p in customPaths ?? [])
                {
                    if (!Add(p))
                    {
                        notes.Add($"Path does not exist: {p}");
                    }
                }

                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }

        return new ScanPlan(mode, roots, depth, notes);

        bool Add(string? path)
        {
            if (string.IsNullOrWhiteSpace(path) || !_env.Exists(path))
            {
                return false;
            }

            var full = Path.GetFullPath(path);
            if (!roots.Contains(full, StringComparer.OrdinalIgnoreCase))
            {
                roots.Add(full);
            }

            return true;
        }

        void AddInventoryTargets()
        {
            if (inventory is null)
            {
                notes.Add("Autostart inventory was not available; autostart targets are not included.");
                return;
            }

            var missing = 0;
            foreach (var e in inventory.Entries.Where(e => e.ImagePath is not null))
            {
                if (!Add(e.ImagePath))
                {
                    missing++;
                }
            }

            if (missing > 0)
            {
                notes.Add($"{missing} autostart entr{(missing == 1 ? "y points" : "ies point")} to a missing file (see inventory).");
            }

            if (inventory.Errors.Count > 0)
            {
                notes.Add($"Inventory was incomplete ({inventory.Errors.Count} error(s)); some autostart targets may be missing.");
            }
        }
    }
}
