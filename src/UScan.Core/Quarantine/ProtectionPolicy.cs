namespace UScan.Core.Quarantine;

/// <summary>Decides whether a file may be moved/removed without an additional, explicit administrator confirmation.</summary>
public interface IFileProtectionPolicy
{
    /// <returns>null if unrestricted, otherwise the reason the file is protected.</returns>
    string? GetProtectionReason(string fullPath);
}

/// <summary>
/// Protects operating-system and program directories. A false positive there can make the
/// system unbootable, so such files are never quarantined automatically.
/// </summary>
public sealed class ProtectedLocationsPolicy : IFileProtectionPolicy
{
    private readonly string[] _roots;

    public ProtectedLocationsPolicy(IEnumerable<string> protectedRoots)
    {
        ArgumentNullException.ThrowIfNull(protectedRoots);
        _roots = protectedRoots
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => Path.TrimEndingDirectorySeparator(Path.GetFullPath(r)))
            .Distinct(PathComparer)
            .ToArray();
    }

    private static StringComparer PathComparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static ProtectedLocationsPolicy ForCurrentOs()
    {
        if (OperatingSystem.IsWindows())
        {
            return new ProtectedLocationsPolicy(
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft"),
                Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Recovery"),
                Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Boot"),
            ]);
        }

        return new ProtectedLocationsPolicy(["/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot"]);
    }

    public string? GetProtectionReason(string fullPath)
    {
        var p = Path.GetFullPath(fullPath);
        foreach (var root in _roots)
        {
            if (p.Equals(root, PathComparison)
                || (p.StartsWith(root, PathComparison) && p.Length > root.Length && (p[root.Length] == Path.DirectorySeparatorChar || p[root.Length] == Path.AltDirectorySeparatorChar)))
            {
                return $"Located in protected system location '{root}'.";
            }
        }

        return null;
    }
}

/// <summary>Combines several policies; the first reason wins.</summary>
public sealed class CompositeProtectionPolicy(params IFileProtectionPolicy[] policies) : IFileProtectionPolicy
{
    public string? GetProtectionReason(string fullPath) =>
        policies.Select(p => p.GetProtectionReason(fullPath)).FirstOrDefault(r => r is not null);
}
