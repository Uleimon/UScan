using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using UScan.Core.Inventory;

namespace UScan.Windows.Inventory;

/// <summary>
/// Services from the registry (ImagePath, start type) cross-checked with the Service Control
/// Manager. A service present in one inventory but not the other is reported as an
/// inconsistency – a hint worth reviewing, not proof of a rootkit.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceSource(InventoryEntryFactory factory, bool includeDisabled = false) : IInventorySource
{
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    public string Name => "Services";

    public IEnumerable<InventoryEntry> Collect(ICollection<string> errors)
    {
        var scm = new Dictionary<string, ServiceController>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var s in ServiceController.GetServices().Concat(ServiceController.GetDevices()))
            {
                scm[s.ServiceName] = s;
            }
        }
        catch (InvalidOperationException ex)
        {
            errors.Add($"Service Control Manager: {ex.Message}");
        }

        var result = new List<InventoryEntry>();
        var seenInRegistry = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var services = Registry.LocalMachine.OpenSubKey(ServicesKey, writable: false);
        if (services is null)
        {
            errors.Add("Services registry key not readable.");
            return result;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            using var key = services.OpenSubKey(name);
            var image = key?.GetValue("ImagePath", null, RegistryValueOptions.None)?.ToString();
            var type = key?.GetValue("Type") is int t ? t : 0;
            if (image is null || (type & 0x30) == 0 && (type & 0x3) == 0)
            {
                continue; // not a service/driver definition (e.g. parameters only)
            }

            seenInRegistry.Add(name);
            var start = key?.GetValue("Start") is int s ? s : -1;
            if (start == 4 && !includeDisabled)
            {
                continue;
            }

            var notes = new List<string> { $"Start type: {StartName(start)}", (type & 0x3) != 0 ? "Kernel/file-system driver." : "Win32 service." };
            if (!scm.ContainsKey(name))
            {
                notes.Add("Defined in the registry but not reported by the Service Control Manager (inconsistency).");
            }

            if (key?.GetValue("ServiceDll", null) is null && key?.OpenSubKey("Parameters")?.GetValue("ServiceDll")?.ToString() is { } serviceDll)
            {
                notes.Add($"svchost service DLL: {serviceDll}");
                result.Add(factory.Create(InventoryKind.Service, $@"HKLM\{ServicesKey}\{name}", name, $"\"{Environment.ExpandEnvironmentVariables(serviceDll)}\"", notes));
                continue;
            }

            result.Add(factory.Create(InventoryKind.Service, $@"HKLM\{ServicesKey}\{name}", name, image, notes));
        }

        foreach (var name in scm.Keys.Where(n => !seenInRegistry.Contains(n)))
        {
            result.Add(new InventoryEntry(InventoryKind.Service, "Service Control Manager", name, null, null, null, null, null,
                ["Reported by the Service Control Manager but no registry definition was readable (inconsistency)."]));
        }

        foreach (var s in scm.Values)
        {
            s.Dispose();
        }

        return result;
    }

    private static string StartName(int start) => start switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    };
}
