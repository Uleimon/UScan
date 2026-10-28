using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using UScan.Core.Inventory;

namespace UScan.Windows.Inventory;

/// <summary>Per-user and all-users Startup folders. Shortcuts are resolved through the WScript.Shell COM object (read-only).</summary>
[SupportedOSPlatform("windows")]
public sealed class StartupFolderSource(InventoryEntryFactory factory) : IInventorySource
{
    public string Name => "Startup folders";

    public IEnumerable<InventoryEntry> Collect(ICollection<string> errors)
    {
        var result = new List<InventoryEntry>();
        foreach (var folder in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
        {
            var dir = Environment.GetFolderPath(folder);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(dir))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    var target = TryResolveShortcut(file, errors);
                    result.Add(factory.Create(InventoryKind.StartupFolder, dir, name, target ?? file,
                        target is null ? ["Shortcut target could not be resolved."] : null));
                }
                else
                {
                    result.Add(factory.Create(InventoryKind.StartupFolder, dir, name, $"\"{file}\"", ["File placed directly in the Startup folder."]));
                }
            }
        }

        return result;
    }

    private static string? TryResolveShortcut(string lnk, ICollection<string> errors)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null)
        {
            errors.Add("WScript.Shell COM object is not available; shortcuts not resolved.");
            return null;
        }

        object? shell = null;
        try
        {
            shell = Activator.CreateInstance(type);
            dynamic sc = ((dynamic)shell!).CreateShortcut(lnk);
            string path = sc.TargetPath;
            string args = sc.Arguments;
            return string.IsNullOrEmpty(path) ? null : $"\"{path}\" {args}".Trim();
        }
        catch (COMException ex)
        {
            errors.Add($"{lnk}: {ex.Message}");
            return null;
        }
        finally
        {
            if (shell is not null)
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }
}
