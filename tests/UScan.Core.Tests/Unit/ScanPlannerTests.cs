using UScan.Core.Inventory;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public sealed class ScanPlannerTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private sealed class FakeEnv(TempDir dir) : IScanEnvironment
    {
        public string? GetFolder(Environment.SpecialFolder folder) => folder switch
        {
            Environment.SpecialFolder.DesktopDirectory => Path.Combine(dir.Path, "Desktop"),
            Environment.SpecialFolder.UserProfile => dir.Path,
            Environment.SpecialFolder.ApplicationData => Path.Combine(dir.Path, "NotCreated"),
            _ => null,
        };

        public string? TempPath => Path.Combine(dir.Path, "Temp");
        public IEnumerable<string> FixedDriveRoots() => [Path.Combine(dir.Path, "C"), Path.Combine(dir.Path, "D")];
        public bool Exists(string path) => File.Exists(path) || Directory.Exists(path);
    }

    private ScanPlanner Planner()
    {
        foreach (var d in new[] { "Desktop", "Downloads", "Temp", "C", "D" })
        {
            Directory.CreateDirectory(Path.Combine(_dir.Path, d));
        }

        return new ScanPlanner(new FakeEnv(_dir));
    }

    private InventorySnapshot Inventory(params string?[] images) => new(
        DateTimeOffset.UtcNow,
        images.Select((p, i) => new InventoryEntry(InventoryKind.Service, "l", $"s{i}", p, p, p is null ? null : File.Exists(p), null, null, [])).ToArray(),
        []);

    [Fact]
    public void Quick_scan_covers_existing_user_locations_and_autostart_targets()
    {
        var planner = Planner();
        var exe = _dir.Write(Path.Combine("Programs", "svc.exe"), "x");
        var plan = planner.Create(ScanMode.Quick, Inventory(exe, exe, Path.Combine(_dir.Path, "missing.exe"), null));

        Assert.Equal(
            new[] { "Desktop", "Downloads", "Temp" }.Select(d => Path.Combine(_dir.Path, d)).Append(exe),
            plan.Roots);
        Assert.Equal(4, plan.MaxDirectoryDepth);
        Assert.Contains(plan.Notes, n => n.Contains("1 autostart entry points to a missing file", StringComparison.Ordinal));
        Assert.Contains(plan.Notes, n => n.Contains("not checked", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_inventory_is_stated_not_hidden()
    {
        var plan = Planner().Create(ScanMode.Autostart);
        Assert.Empty(plan.Roots);
        Assert.Contains(plan.Notes, n => n.Contains("not available", StringComparison.Ordinal));
    }

    [Fact]
    public void Full_and_custom_modes()
    {
        var planner = Planner();
        Assert.Equal(2, planner.Create(ScanMode.Full).Roots.Count);

        var custom = planner.Create(ScanMode.Custom, customPaths: [Path.Combine(_dir.Path, "C"), Path.Combine(_dir.Path, "nope")]);
        Assert.Single(custom.Roots);
        Assert.Contains(custom.Notes, n => n.Contains("does not exist", StringComparison.Ordinal));
    }
}
