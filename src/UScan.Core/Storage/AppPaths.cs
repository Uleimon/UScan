namespace UScan.Core.Storage;

/// <summary>
/// All on-disk locations used by UScan, derived from one root so tests can use a temp folder.
/// Default root is per user (%LOCALAPPDATA%\UScan on Windows), which needs no elevation and
/// is not readable by other standard users.
/// </summary>
public sealed class AppPaths
{
    public AppPaths(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        Root = Path.GetFullPath(root);
    }

    public static AppPaths Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create),
        "UScan"));

    public string Root { get; }
    public string Logs => Path.Combine(Root, "logs");
    public string Reports => Path.Combine(Root, "reports");
    public string Quarantine => Path.Combine(Root, "quarantine");
    public string Settings => Path.Combine(Root, "settings.json");
    public string Baselines => Path.Combine(Root, "baselines");
}
