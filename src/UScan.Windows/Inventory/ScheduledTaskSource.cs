using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using UScan.Core.Inventory;

namespace UScan.Windows.Inventory;

/// <summary>Scheduled tasks (including hidden ones) via the Task Scheduler 2.0 COM API, read-only.</summary>
[SupportedOSPlatform("windows")]
public sealed class ScheduledTaskSource(InventoryEntryFactory factory) : IInventorySource
{
    private const int TASK_ENUM_HIDDEN = 1;
    private const int TASK_ACTION_EXEC = 0;

    public string Name => "Scheduled tasks";

    public IEnumerable<InventoryEntry> Collect(ICollection<string> errors)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("Task Scheduler COM API not available.");
        var result = new List<InventoryEntry>();
        dynamic service = Activator.CreateInstance(type)!;
        try
        {
            service.Connect();
            Walk(service.GetFolder("\\"), result, errors);
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }

        return result;
    }

    private void Walk(dynamic folder, List<InventoryEntry> result, ICollection<string> errors)
    {
        string folderPath = folder.Path;
        try
        {
            foreach (dynamic task in folder.GetTasks(TASK_ENUM_HIDDEN))
            {
                try
                {
                    string name = task.Name;
                    bool enabled = task.Enabled;
                    dynamic def = task.Definition;
                    bool hidden = def.Settings.Hidden;
                    string? author = def.RegistrationInfo.Author;
                    foreach (dynamic action in def.Actions)
                    {
                        if ((int)action.Type != TASK_ACTION_EXEC)
                        {
                            continue;
                        }

                        string path = action.Path ?? "";
                        string args = action.Arguments ?? "";
                        var cmd = path.Contains(' ', StringComparison.Ordinal) && !path.StartsWith('"') ? $"\"{path}\" {args}" : $"{path} {args}";
                        var notes = new List<string>();
                        if (!enabled)
                        {
                            notes.Add("Task is disabled.");
                        }

                        if (hidden)
                        {
                            notes.Add("Task is marked hidden.");
                        }

                        if (!string.IsNullOrEmpty(author))
                        {
                            notes.Add($"Author: {author}");
                        }

                        result.Add(factory.Create(InventoryKind.ScheduledTask, folderPath, name, cmd.Trim(), notes));
                    }
                }
                catch (COMException ex)
                {
                    errors.Add($"{folderPath}: {ex.Message}");
                }
            }

            foreach (dynamic sub in folder.GetFolders(0))
            {
                Walk(sub, result, errors);
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
        {
            errors.Add($"{folderPath}: {ex.Message}");
        }
    }
}
