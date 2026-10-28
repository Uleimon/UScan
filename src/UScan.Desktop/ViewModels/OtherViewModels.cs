using System.IO;
using System.Collections.ObjectModel;
using System.Windows;
using UScan.Core.App;
using UScan.Core.Inventory;
using UScan.Core.Model;
using UScan.Core.Monitoring;
using UScan.Core.Quarantine;
using UScan.Core.Storage;

namespace UScan.Desktop.ViewModels;

internal sealed class QuarantineViewModel : ObservableObject
{
    private readonly UScanHost _host;
    private readonly IDialogs _dialogs;
    private readonly Func<Task> _changed;
    private QuarantineItem? _selected;
    private string _message = "";

    public QuarantineViewModel(UScanHost host, IDialogs dialogs, Func<Task> changed)
    {
        _host = host;
        _dialogs = dialogs;
        _changed = changed;
        RestoreCommand = new AsyncCommand(RestoreAsync, () => Selected is not null);
        DeleteCommand = new AsyncCommand(DeleteAsync, () => Selected is not null);
        VerifyCommand = new AsyncCommand(VerifyAsync, () => Selected is not null);
    }

    public ObservableCollection<QuarantineItem> Items { get; } = [];
    public QuarantineItem? Selected { get => _selected; set => Set(ref _selected, value); }
    public string Message { get => _message; private set => Set(ref _message, value); }
    public AsyncCommand RestoreCommand { get; }
    public AsyncCommand DeleteCommand { get; }
    public AsyncCommand VerifyCommand { get; }

    public void Refresh()
    {
        Items.Clear();
        foreach (var i in _host.Quarantine.List())
        {
            Items.Add(i);
        }
    }

    private async Task RestoreAsync()
    {
        var item = Selected!;
        if (!_dialogs.Confirm("Wiederherstellen", $"{item.OriginalPath}\nFund: {item.DetectionName}\n\nDie Datei wird vor dem Wiederherstellen erneut gescannt. Eine vorhandene Datei wird nie überschrieben."))
        {
            return;
        }

        var r = await _host.Quarantine.RestoreAsync(item.Id, _host.Engine, null, false, CancellationToken.None);
        if (!r.Success && r.RescanVerdict is Verdict.Infected or Verdict.Suspicious &&
            _dialogs.Confirm("Trotz Fund wiederherstellen?", $"Der Nachscan meldet die Datei weiterhin als {Texts.Verdict(r.RescanVerdict.Value)}.\n\nNur wiederherstellen, wenn Sie sicher sind, dass es ein Fehlalarm ist.", dangerous: true))
        {
            r = await _host.Quarantine.RestoreAsync(item.Id, _host.Engine, null, true, CancellationToken.None);
        }

        Message = r.Message;
        Refresh();
        await _changed();
    }

    private async Task DeleteAsync()
    {
        var item = Selected!;
        if (!_dialogs.Confirm("Endgültig löschen", $"{item.OriginalPath}\nFund: {item.DetectionName}\n\nDas Objekt wird endgültig gelöscht. Das kann nicht rückgängig gemacht werden.", dangerous: true))
        {
            return;
        }

        Message = _host.Quarantine.DeletePermanently(item.Id, userConfirmed: true) ? "Endgültig gelöscht." : "Löschen fehlgeschlagen.";
        Refresh();
        await _changed();
    }

    private async Task VerifyAsync()
    {
        Message = await _host.Quarantine.VerifyAsync(Selected!.Id) ? "Objekt ist unversehrt (Authentifizierung und SHA-256 stimmen)." : "Objekt ist beschädigt oder fehlt.";
    }
}

internal sealed class InventoryRow(InventoryEntry e, string? change = null)
{
    public string Kind => e.Kind.ToString();
    public string Name => e.Name;
    public string Command => e.Command ?? "";
    public string File => e.ImagePath ?? "?";
    public string Exists => e.FileExists switch { true => "ja", false => "NEIN", null => "?" };
    public string Signature => e.Signature is { } s ? s.Status + (s.Signer is null ? "" : $" ({s.Signer})") : "nicht geprüft";
    public bool Trusted => e.Signature?.IsTrusted == true;
    public string Observations => string.Join("; ", e.Observations);
    public string Change => change ?? "";
}

internal sealed class InventoryViewModel : ObservableObject
{
    private readonly UScanHost _host;
    private string _message = "Noch nicht geladen.";

    public InventoryViewModel(UScanHost host)
    {
        _host = host;
        LoadCommand = new AsyncCommand(LoadAsync);
        ChangesCommand = new AsyncCommand(ChangesAsync);
    }

    public ObservableCollection<InventoryRow> Entries { get; } = [];
    public string Message { get => _message; private set => Set(ref _message, value); }
    public AsyncCommand LoadCommand { get; }
    public AsyncCommand ChangesCommand { get; }

    private async Task LoadAsync()
    {
        Message = "Autostart-Einträge, Dienste und geplante Aufgaben werden gelesen und Signaturen geprüft …";
        var snap = await Task.Run(() => _host.CreateInventoryCollector().Collect());
        Entries.Clear();
        foreach (var e in snap.Entries.OrderBy(e => e.Signature?.IsTrusted == true).ThenBy(e => e.Kind).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            Entries.Add(new InventoryRow(e));
        }

        Message = $"{snap.Entries.Count} Einträge, davon {snap.Entries.Count(e => e.Signature?.IsTrusted != true)} ohne vertrauenswürdige Signatur. " +
                  "Beobachtungen sind Fakten, keine Schadsoftware-Urteile." +
                  (snap.Errors.Count > 0 ? $" Nicht vollständig gelesen: {string.Join("; ", snap.Errors)}" : "");
    }

    private async Task ChangesAsync()
    {
        var check = await Task.Run(() => _host.CreateAutostartMonitor().Check());
        Entries.Clear();
        foreach (var c in check.Changes)
        {
            Entries.Add(new InventoryRow(c.Entry, c.ChangeType));
        }

        Message = check.BaselineCreated
            ? "Ausgangszustand gespeichert. Ab jetzt werden neue und geänderte Einträge erkannt."
            : check.Changes.Count == 0 ? "Keine Änderungen seit der letzten Prüfung." : $"{check.Changes.Count} Änderung(en) seit der letzten Prüfung.";
    }
}

internal sealed class MonitorViewModel : ObservableObject, IDisposable
{
    private readonly UScanHost _host;
    private readonly Func<Task> _changed;
    private FileWatchService? _watcher;
    private Timer? _heartbeat;
    private string _folders;
    private string _state = "Aus";

    public MonitorViewModel(UScanHost host, Func<Task> changed)
    {
        _host = host;
        _changed = changed;
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _folders = string.Join(Environment.NewLine, host.Settings.WatchFolders.Count > 0
            ? host.Settings.WatchFolders
            : [Path.Combine(profile, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)]);
        StartCommand = new AsyncCommand(StartAsync, () => _watcher is null);
        StopCommand = new AsyncCommand(StopAsync, () => _watcher is not null);
    }

    public ObservableCollection<string> Events { get; } = [];
    public string Folders { get => _folders; set => Set(ref _folders, value); }
    public string State { get => _state; private set => Set(ref _state, value); }
    public AsyncCommand StartCommand { get; }
    public AsyncCommand StopCommand { get; }

    private async Task StartAsync()
    {
        var roots = Folders.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(Directory.Exists).ToArray();
        if (roots.Length == 0)
        {
            State = "Keiner der Ordner existiert.";
            return;
        }

        if (!await _host.Engine.PingAsync(CancellationToken.None))
        {
            State = "Nicht gestartet: Scan-Engine (clamd) ist nicht erreichbar.";
            return;
        }

        var w = new FileWatchService(roots, _host.CreateRunner(), new WatchOptions { Exclusions = [_host.Paths.Root] }, _host.Log);
        w.FileScanned += r =>
        {
            if (r.Verdict is Verdict.Infected or Verdict.Suspicious or Verdict.Error)
            {
                Post($"{Texts.Verdict(r.Verdict)}: {r.Path} {r.DetectionName ?? r.Message}");
            }
        };
        w.Warning += m => Post("Warnung: " + m);
        w.Start();
        _watcher = w;
        MonitorHeartbeat.Write(_host.HeartbeatFile, roots);
        _heartbeat = new Timer(_ => MonitorHeartbeat.Write(_host.HeartbeatFile, roots), null, MonitorHeartbeat.Interval, MonitorHeartbeat.Interval);
        State = $"Läuft: {string.Join(", ", roots)}. Geänderte Dateien werden kurz danach gescannt; Zugriffe werden nicht blockiert.";
        await _changed();
    }

    public void Dispose()
    {
        _heartbeat?.Dispose();
        _heartbeat = null;
    }

    public async Task StopAsync()
    {
        if (_heartbeat is not null)
        {
            await _heartbeat.DisposeAsync();
            _heartbeat = null;
        }

        if (_watcher is not null)
        {
            await _watcher.StopAsync();
            _watcher = null;
            MonitorHeartbeat.Clear(_host.HeartbeatFile);
        }

        State = "Aus";
        await _changed();
    }

    private void Post(string text) =>
        Application.Current?.Dispatcher.InvokeAsync(async () =>
        {
            Events.Insert(0, $"{DateTime.Now:HH:mm:ss} {text}");
            await _changed();
        });
}

internal sealed class LogViewModel : ObservableObject
{
    private readonly UScanHost _host;

    public LogViewModel(UScanHost host)
    {
        _host = host;
        RefreshCommand = new RelayCommand(_ => Refresh());
    }

    public ObservableCollection<SecurityEvent> Events { get; } = [];
    public RelayCommand RefreshCommand { get; }

    public void Refresh()
    {
        Events.Clear();
        foreach (var e in _host.Log.ReadRecent(500).Reverse())
        {
            Events.Add(e);
        }
    }
}
