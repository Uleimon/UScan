using System.Collections.ObjectModel;
using System.Globalization;
using UScan.Core.App;
using UScan.Core.Status;

namespace UScan.Desktop.ViewModels;

internal sealed class OpenDetectionRow(OpenDetection detection)
{
    public OpenDetection Detection { get; } = detection;
    public string Text => $"{Texts.Verdict(Detection.Verdict)}: {Detection.Path} ({Detection.DetectionName})";
}

/// <summary>Overview page. Every value comes from <see cref="UScanHost.GetStatusAsync"/>; nothing is assumed.</summary>
internal sealed class DashboardViewModel : ObservableObject
{
    private readonly UScanHost _host;
    private readonly Func<bool> _scanRunning;
    private readonly IDialogs? _dialogs;
    private ProtectionState _state = ProtectionState.Unknown;
    private string _engine = "wird ermittelt …";
    private string _signatures = "wird ermittelt …";
    private string _onAccess = "wird ermittelt …";
    private string _monitor = "wird ermittelt …";
    private string _quarantine = "";
    private string _lastScan = "";
    private string _updateMessage = "";
    private DateTimeOffset? _checkedAt;

    public DashboardViewModel(UScanHost host, Func<bool> scanRunning, IDialogs? dialogs = null)
    {
        _host = host;
        _scanRunning = scanRunning;
        _dialogs = dialogs;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        UpdateSignaturesCommand = new AsyncCommand(UpdateSignaturesAsync);
        QuarantineDetectionCommand = new AsyncCommand(p => QuarantineDetectionAsync((OpenDetectionRow)p!), p => p is OpenDetectionRow && _dialogs is not null);
        AllowDetectionCommand = new AsyncCommand(p => AllowDetectionAsync((OpenDetectionRow)p!), p => p is OpenDetectionRow && _dialogs is not null);
    }

    public AsyncCommand RefreshCommand { get; }
    public AsyncCommand UpdateSignaturesCommand { get; }
    public AsyncCommand QuarantineDetectionCommand { get; }
    public AsyncCommand AllowDetectionCommand { get; }

    public ProtectionState State
    {
        get => _state;
        private set
        {
            if (Set(ref _state, value))
            {
                OnPropertyChanged(nameof(StateText));
                OnPropertyChanged(nameof(StateBrushKey));
            }
        }
    }

    public string StateText => Texts.State(State);
    public string StateBrushKey => Texts.StateBrushKey(State);
    public ObservableCollection<string> Reasons { get; } = [];
    public ObservableCollection<OpenDetectionRow> OpenDetections { get; } = [];
    public string Engine { get => _engine; private set => Set(ref _engine, value); }
    public string Signatures { get => _signatures; private set => Set(ref _signatures, value); }
    public string OnAccess { get => _onAccess; private set => Set(ref _onAccess, value); }
    public string Monitor { get => _monitor; private set => Set(ref _monitor, value); }
    public string Quarantine { get => _quarantine; private set => Set(ref _quarantine, value); }
    public string LastScan { get => _lastScan; private set => Set(ref _lastScan, value); }
    public string UpdateMessage { get => _updateMessage; private set => Set(ref _updateMessage, value); }
    public string CheckedAt => _checkedAt is { } t ? $"Stand: {t.ToLocalTime():HH:mm:ss}" : "";

    public async Task RefreshAsync()
    {
        var s = await _host.GetStatusAsync(_scanRunning(), CancellationToken.None);
        State = s.Assessment.State;
        Reasons.Clear();
        foreach (var r in s.Assessment.Reasons)
        {
            Reasons.Add(r);
        }

        if (s.SettingsError is not null)
        {
            Reasons.Add(s.SettingsError);
        }

        OpenDetections.Clear();
        foreach (var d in s.OpenDetections)
        {
            OpenDetections.Add(new OpenDetectionRow(d));
        }

        Engine = s.EngineReachable ? $"ClamAV {s.Engine?.EngineVersion ?? "?"} – erreichbar" : "ClamAV-Dienst (clamd) NICHT erreichbar";
        Signatures = s.Engine?.DatabaseVersion is { } v
            ? string.Create(CultureInfo.InvariantCulture, $"Version {v}, Stand {s.Engine.DatabaseTimestamp?.ToLocalTime():dd.MM.yyyy HH:mm}")
            : "Keine offizielle Signaturdatenbank erkannt";
        OnAccess = (s.OnAccess.Active switch { true => "Aktiv. ", false => "AUS. ", null => "Unbekannt. " }) + s.OnAccess.Detail;
        Monitor = s.MonitoredFolders is { } m ? $"Läuft: {string.Join(", ", m)} (Nachscan nach Änderung, blockiert nicht)" : "Läuft nicht";
        Quarantine = $"{s.QuarantineCount} Objekt(e)" + (s.QuarantineNeedingAction.Count > 0 ? $", bei {s.QuarantineNeedingAction.Count} ist das Original noch vorhanden" : "");
        LastScan = s.LastScan is { } l ? l.ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture) : "Noch kein Scan";
        _checkedAt = DateTimeOffset.Now;
        OnPropertyChanged(nameof(CheckedAt));
    }

    internal async Task QuarantineDetectionAsync(OpenDetectionRow row)
    {
        var d = row.Detection;
        if (!_dialogs!.Confirm("In Quarantäne verschieben",
                $"{d.Path}\nFund: {d.DetectionName}\n\nDie Datei wird verschlüsselt in die Quarantäne verschoben und am Originalort entfernt. Sie kann später wiederhergestellt werden."))
        {
            return;
        }

        var r = await _host.Quarantine.QuarantineAsync(d.Path, d.DetectionName ?? Texts.Verdict(d.Verdict), "report", d.Sha256, false, CancellationToken.None);
        if (!r.Success && r.Message.StartsWith("Protected file", StringComparison.Ordinal) &&
            _dialogs.Confirm("Geschützte Datei", $"{d.Path}\n\n{r.Message}\n\nNur fortfahren, wenn Sie Administrator sind und den Fund geprüft haben. Trotzdem verschieben?", dangerous: true))
        {
            r = await _host.Quarantine.QuarantineAsync(d.Path, d.DetectionName ?? Texts.Verdict(d.Verdict), "report", d.Sha256, true, CancellationToken.None);
        }

        UpdateMessage = r.Success ? $"In Quarantäne verschoben: {d.Path}" : $"Nicht verschoben: {r.Message}";
        await RefreshAsync();
    }

    internal async Task AllowDetectionAsync(OpenDetectionRow row)
    {
        var d = row.Detection;
        if (!_dialogs!.Confirm("Als Fehlalarm zulassen",
                $"{d.Path}\nFund: {d.DetectionName}\n\nNur zulassen, wenn Sie sicher sind, dass die Datei harmlos ist (z. B. frisch von der offiziellen Herstellerseite). " +
                "Die Freigabe gilt nur für genau diesen Dateiinhalt; ändert sich die Datei, wird sie wieder gemeldet. Die Freigabe wird protokolliert.", dangerous: true))
        {
            return;
        }

        var refused = _host.AllowOpenDetection(d.Path, $"Fehlalarm, in der Oberfläche zugelassen ({d.DetectionName})");
        UpdateMessage = refused is null ? $"Als Fehlalarm zugelassen: {d.Path}" : $"Nicht zugelassen: {refused}";
        await RefreshAsync();
    }

    private async Task UpdateSignaturesAsync()
    {
        UpdateMessage = "Signaturen werden mit freshclam aktualisiert …";
        var r = await _host.CreateSignatureUpdater().UpdateAsync(CancellationToken.None);
        UpdateMessage = r.Summary;
        await RefreshAsync();
    }
}
