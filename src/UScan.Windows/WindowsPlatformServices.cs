using System.Management;
using System.Runtime.Versioning;
using UScan.Core.App;
using UScan.Core.Engines;
using UScan.Core.Inventory;
using UScan.Core.Quarantine;
using UScan.Windows.Authenticode;
using UScan.Windows.Defender;
using UScan.Windows.Inventory;

namespace UScan.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsPlatformServices : IPlatformServices
{
    public string Name => "windows";

    public ISignatureVerifier Signatures { get; } = new AuthenticodeVerifier();

    public IFileProtectionPolicy ProtectionPolicy { get; } = ProtectedLocationsPolicy.ForCurrentOs();

    public IReadOnlyList<IInventorySource> CreateInventorySources(InventoryEntryFactory factory) =>
    [
        new RegistryAutostartSource(factory),
        new StartupFolderSource(factory),
        new ServiceSource(factory),
        new ScheduledTaskSource(factory),
    ];

    public IFileScanEngine? CreateSecondOpinion() => DefenderEngine.TryCreate();

    public string DefaultFreshclamPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", "freshclam.exe");

    /// <summary>
    /// Microsoft Defender's own report is authoritative for Defender. If Defender is not active,
    /// another antivirus may be; Windows Security Center lists registered products, but their
    /// real-time state is not exposed through a documented interface, so it is reported as unknown.
    /// </summary>
    public OnAccessProtection QueryOnAccessProtection()
    {
        var defender = DefenderStatusProvider.Query();
        if (defender.Available && defender.AntivirusEnabled == true && defender.RealTimeProtectionEnabled == true)
        {
            return new OnAccessProtection(true, $"Microsoft Defender real-time protection is on (signatures {defender.SignatureVersion ?? "?"}).");
        }

        var others = RegisteredAntivirusProducts().Where(n => !n.Contains("Defender", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (others.Length > 0)
        {
            return new OnAccessProtection(null, $"Microsoft Defender real-time protection is not active; registered antivirus: {string.Join(", ", others)}. Its real-time state cannot be read reliably.");
        }

        if (!defender.Available)
        {
            return new OnAccessProtection(null, $"Microsoft Defender status unavailable: {defender.Error}");
        }

        return new OnAccessProtection(false, "Microsoft Defender real-time protection is off and no other antivirus is registered.");
    }

    private static string[] RegisteredAntivirusProducts()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct");
            return searcher.Get().Cast<ManagementObject>().Select(o =>
            {
                using (o)
                {
                    return o["displayName"] as string;
                }
            }).OfType<string>().ToArray();
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            // Not available on Windows Server editions.
            return [];
        }
    }
}
