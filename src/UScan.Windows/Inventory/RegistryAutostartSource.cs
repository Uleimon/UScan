using System.Runtime.Versioning;
using Microsoft.Win32;
using UScan.Core.Inventory;

namespace UScan.Windows.Inventory;

/// <summary>
/// Reads the documented registry autostart locations (read-only):
/// Run/RunOnce for machine and user, 32-bit views, Winlogon Shell/Userinit,
/// Image File Execution Options "Debugger" hijacks and AppInit_DLLs.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryAutostartSource(InventoryEntryFactory factory) : IInventorySource
{
    private static readonly (RegistryHive Hive, string Path)[] RunKeys =
    [
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ];

    private const string Winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string Windows = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    public string Name => "Registry autostart";

    public IEnumerable<InventoryEntry> Collect(ICollection<string> errors)
    {
        var result = new List<InventoryEntry>();
        foreach (var (hive, path) in RunKeys)
        {
            WithKey(hive, path, errors, key =>
            {
                foreach (var name in key.GetValueNames())
                {
                    var cmd = key.GetValue(name, null, RegistryValueOptions.None)?.ToString();
                    result.Add(factory.Create(InventoryKind.RegistryRun, $@"{HiveName(hive)}\{path}", name.Length == 0 ? "(Default)" : name, cmd));
                }
            });
        }

        WithKey(RegistryHive.LocalMachine, Winlogon, errors, key =>
        {
            // Expected defaults: Shell = explorer.exe, Userinit = C:\Windows\system32\userinit.exe,
            foreach (var (value, expected) in new[] { ("Shell", "explorer.exe"), ("Userinit", @"\system32\userinit.exe,") })
            {
                var v = key.GetValue(value)?.ToString();
                if (v is null)
                {
                    continue;
                }

                var notes = v.Trim().EndsWith(expected, StringComparison.OrdinalIgnoreCase) || v.Trim().Equals(expected.TrimEnd(','), StringComparison.OrdinalIgnoreCase)
                    ? Array.Empty<string>()
                    : [$"Differs from the Windows default (expected to end with '{expected}')."];
                var first = v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
                result.Add(factory.Create(InventoryKind.WinlogonValue, $@"HKLM\{Winlogon}", value, first, notes));
            }
        });

        WithKey(RegistryHive.LocalMachine, Ifeo, errors, key =>
        {
            foreach (var sub in key.GetSubKeyNames())
            {
                using var s = key.OpenSubKey(sub);
                if (s?.GetValue("Debugger")?.ToString() is { Length: > 0 } dbg)
                {
                    result.Add(factory.Create(InventoryKind.ImageFileExecutionOptions, $@"HKLM\{Ifeo}\{sub}", "Debugger", dbg,
                        [$"Starting '{sub}' launches this program instead (debugger redirection)."]));
                }
            }
        });

        WithKey(RegistryHive.LocalMachine, Windows, errors, key =>
        {
            var dlls = key.GetValue("AppInit_DLLs")?.ToString();
            var enabled = key.GetValue("LoadAppInit_DLLs") is int i && i != 0;
            if (!string.IsNullOrWhiteSpace(dlls))
            {
                foreach (var dll in dlls.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries))
                {
                    result.Add(factory.Create(InventoryKind.AppInitDll, $@"HKLM\{Windows}", "AppInit_DLLs", dll,
                        [enabled ? "AppInit_DLLs is enabled: DLL is loaded into every process that loads user32.dll." : "AppInit_DLLs is set but LoadAppInit_DLLs is disabled."]));
                }
            }
        });

        return result;
    }

    private static void WithKey(RegistryHive hive, string path, ICollection<string> errors, Action<RegistryKey> action)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = root.OpenSubKey(path, writable: false);
            if (key is not null)
            {
                action(key);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            errors.Add($@"{HiveName(hive)}\{path}: {ex.Message}");
        }
    }

    private static string HiveName(RegistryHive hive) => hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
}
