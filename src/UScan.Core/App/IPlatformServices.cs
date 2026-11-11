using UScan.Core.Engines;
using UScan.Core.Inventory;
using UScan.Core.Quarantine;

namespace UScan.Core.App;

/// <param name="Active">true/false only when positively known; null when it cannot be determined.</param>
/// <param name="Detail">Human-readable source of the information.</param>
public sealed record OnAccessProtection(bool? Active, string Detail);

/// <summary>ClamAV installed and managed by the UScan setup (next to UScan.exe, clamd as a service).</summary>
public sealed record ManagedClamAV(string Directory, string FreshclamPath, string FreshclamConfig);

/// <summary>Operating-system specific parts. Windows: UScan.Windows.WindowsPlatformServices.</summary>
public interface IPlatformServices
{
    string Name { get; }
    ISignatureVerifier Signatures { get; }
    IFileProtectionPolicy ProtectionPolicy { get; }
    IReadOnlyList<IInventorySource> CreateInventorySources(InventoryEntryFactory factory);

    /// <summary>null when no second engine is installed.</summary>
    IFileScanEngine? CreateSecondOpinion();

    OnAccessProtection QueryOnAccessProtection();

    string DefaultFreshclamPath { get; }

    /// <summary>The ClamAV the setup installed and manages, or null. It takes precedence over settings.json.</summary>
    ManagedClamAV? ManagedClamAV { get; }

    /// <summary>
    /// Asks the operating system to start the clamd service if it is installed and stopped.
    /// Returns true only if a start was requested; whether clamd comes up is checked by the caller.
    /// </summary>
    bool TryStartEngineService();

    /// <summary>
    /// Lowers this process's CPU, disk and memory priority until the result is disposed, so a scan
    /// yields to whatever the user is doing. Returns null when the platform has no such mode.
    /// </summary>
    IDisposable? EnterBackgroundMode();
}

/// <summary>Non-Windows hosts (development, CI): scanning works, Windows-only features report "not available".</summary>
public sealed class GenericPlatformServices : IPlatformServices
{
    public string Name => "generic";
    public ISignatureVerifier Signatures { get; } = new NoSignatureVerifier();
    public IFileProtectionPolicy ProtectionPolicy { get; } = ProtectedLocationsPolicy.ForCurrentOs();
    public IReadOnlyList<IInventorySource> CreateInventorySources(InventoryEntryFactory factory) => [];
    public IFileScanEngine? CreateSecondOpinion() => null;
    public OnAccessProtection QueryOnAccessProtection() => new(null, "On-access protection can only be queried on Windows.");
    public string DefaultFreshclamPath => "/usr/bin/freshclam";
    public ManagedClamAV? ManagedClamAV => null;
    public bool TryStartEngineService() => false;
    public IDisposable? EnterBackgroundMode() => null;
}
