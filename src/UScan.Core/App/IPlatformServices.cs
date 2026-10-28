using UScan.Core.Engines;
using UScan.Core.Inventory;
using UScan.Core.Quarantine;

namespace UScan.Core.App;

/// <param name="Active">true/false only when positively known; null when it cannot be determined.</param>
/// <param name="Detail">Human-readable source of the information.</param>
public sealed record OnAccessProtection(bool? Active, string Detail);

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
}
