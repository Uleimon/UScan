using System.Collections.ObjectModel;
using UScan.Core.App;
using UScan.Core.Model;
using UScan.Core.Scanning;

namespace UScan.Desktop.ViewModels;

internal sealed class ScanResultRow(FileScanResult result, bool allowedByUser = false) : ObservableObject
{
    private bool _selected = result.Verdict == Verdict.Infected && !allowedByUser;
    private string _action = "";

    public FileScanResult Result { get; } = result;
    public string Path => Result.Path;
    public string VerdictText => Texts.Verdict(Result.Verdict);
    public string Detail => Result.Verdict == Verdict.Skipped ? $"übersprungen ({Result.SkipReason})"
        : (Result.DetectionName ?? Result.Message ?? "") + (AllowedByUser ? " – von dir als Fehlalarm zugelassen" : "");
    public bool AllowedByUser { get; } = allowedByUser;
    public string Explanation => string.Join(Environment.NewLine, Result.EngineResults.Where(e => e.Verdict != Verdict.Clean && e.Detail is not null).Select(e => $"[{e.EngineId}] {e.Detail}"));
    public bool CanQuarantine => Result.Verdict is Verdict.Infected or Verdict.Suspicious;
    public bool Selected { get => _selected; set => Set(ref _selected, value); }
    public string Action { get => _action; set => Set(ref _action, value); }
}

/// <summary>Runs scans. Progress is only shown as a percentage once the total is known.</summary>
internal sealed class ScanViewModel : ObservableObject, IDisposable
{
    private readonly UScanHost _host;
    private readonly IDialogs _dialogs;
    private readonly Func<Task> _onFinished;
    private CancellationTokenSource? _cts;
    private bool _running;
    private bool _progressKnown;
    private double _progress;
    private string _progressText = "Bereit.";
    private string _summary = "";
    private string _notes = "";
    private bool _hasInterrupted;
    private string _interruptedText = "";
    private bool _paused;
    private string _lastProgressText = "";

    /// <summary>Wait up to about 2 minutes for clamd when a scan starts (it may still be loading). Tests turn it off.</summary>
    internal bool WaitForEngine { get; init; } = true;

    public ScanViewModel(UScanHost host, IDialogs dialogs, Func<Task> onFinished)
    {
        _host = host;
        _dialogs = dialogs;
        _onFinished = onFinished;
        QuickCommand = new AsyncCommand(() => RunAsync(ScanMode.Quick, null), () => !Running);
        FullCommand = new AsyncCommand(() => RunAsync(ScanMode.Full, null), () => !Running);
        AutostartCommand = new AsyncCommand(() => RunAsync(ScanMode.Autostart, null), () => !Running);
        FolderCommand = new AsyncCommand(async () =>
        {
            if (_dialogs.PickFolder() is { } folder)
            {
                await RunAsync(ScanMode.Custom, [folder]);
            }
        }, () => !Running);
        CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => Running);
        PauseCommand = new RelayCommand(_ => TogglePause(), _ => Running);
        ResumeCommand = new AsyncCommand(ResumeAsync, () => !Running && HasInterrupted);
        DiscardCommand = new RelayCommand(_ => Discard(), _ => !Running && HasInterrupted);
        RefreshInterrupted();
        QuarantineCommand = new AsyncCommand(QuarantineSelectedAsync, () => !Running && Results.Any(r => r.Selected && r.CanQuarantine));
    }

    public AsyncCommand QuickCommand { get; }
    public AsyncCommand FullCommand { get; }
    public AsyncCommand AutostartCommand { get; }
    public AsyncCommand FolderCommand { get; }
    public RelayCommand CancelCommand { get; }

    /// <summary>Pauses the running scan, or continues it when it is paused.</summary>
    public RelayCommand PauseCommand { get; }
    public bool Paused
    {
        get => _paused;
        private set
        {
            if (Set(ref _paused, value))
            {
                OnPropertyChanged(nameof(PauseLabel));
            }
        }
    }
    public string PauseLabel => Paused ? "Weiter" : "Pausieren";
    public AsyncCommand ResumeCommand { get; }
    public RelayCommand DiscardCommand { get; }
    public bool HasInterrupted { get => _hasInterrupted; private set => Set(ref _hasInterrupted, value); }
    public string InterruptedText { get => _interruptedText; private set => Set(ref _interruptedText, value); }
    public AsyncCommand QuarantineCommand { get; }

    public ObservableCollection<ScanResultRow> Results { get; } = [];
    public bool Running
    {
        get => _running;
        private set
        {
            if (Set(ref _running, value))
            {
                OnPropertyChanged(nameof(ProgressUnknown));
            }
        }
    }
    public bool ProgressKnown
    {
        get => _progressKnown;
        private set
        {
            if (Set(ref _progressKnown, value))
            {
                OnPropertyChanged(nameof(ProgressUnknown));
            }
        }
    }

    /// <summary>True while scanning and the total number of files is not yet known.</summary>
    public bool ProgressUnknown => Running && !ProgressKnown;
    public double Progress { get => _progress; private set => Set(ref _progress, value); }
    public string ProgressText { get => _progressText; private set => Set(ref _progressText, value); }
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    public string Notes { get => _notes; private set => Set(ref _notes, value); }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    internal async Task RunAsync(ScanMode mode, IReadOnlyList<string>? paths)
    {
        if (_host.InterruptedScan() is { } old && !_dialogs.Confirm("Unterbrochener Scan",
                $"Ein {Texts.Mode(old.Header.Mode)} vom {old.Header.StartedAt.ToLocalTime():g} wurde unterbrochen ({old.FilesDone:N0} Dateien geprüft). " +
                "Wenn Sie einen neuen Scan starten, kann er nicht mehr fortgesetzt werden; ein Teilbericht mit allen Funden bis dahin wird gespeichert.\n\nNeuen Scan trotzdem starten?"))
        {
            return;
        }

        await ExecuteAsync(async (progress, ct) =>
        {
            var plan = await Task.Run(() => _host.Plan(mode, paths), ct);
            Notes = string.Join(Environment.NewLine, plan.Notes);
            if (plan.Roots.Count == 0)
            {
                return null;
            }

            ProgressText = WaitForEngine ? "Verbinde mit clamd … (falls clamd gerade startet, wartet UScan bis zu 2 Minuten)" : "Verbinde mit clamd …";
            return await Task.Run(() => _host.ScanAsync(plan, progress, ct, waitForEngine: WaitForEngine, resumable: true), ct);
        });
    }

    /// <summary>Continues the interrupted scan; unchanged files that were already checked are not scanned again.</summary>
    internal Task ResumeAsync() => ExecuteAsync(async (progress, ct) =>
    {
        ProgressText = $"Setze den unterbrochenen Scan fort … {(WaitForEngine ? "(falls clamd gerade startet, wartet UScan bis zu 2 Minuten)" : "")}";
        return await Task.Run(() => _host.ResumeInterruptedAsync(progress, ct, WaitForEngine), ct);
    });

    private void Discard()
    {
        if (_dialogs.Confirm("Unterbrochenen Scan verwerfen", "Der unterbrochene Scan wird nicht fortgesetzt. Ein Teilbericht mit allen Funden bis dahin wird gespeichert. Fortfahren?"))
        {
            var file = _host.DiscardInterrupted();
            Summary = file is null ? "Unterbrochener Scan verworfen." : $"Unterbrochener Scan verworfen. Teilbericht: {file}";
            RefreshInterrupted();
        }
    }

    /// <summary>Updates the "continue interrupted scan" offer.</summary>
    internal void RefreshInterrupted()
    {
        var interrupted = _host.InterruptedScan();
        HasInterrupted = interrupted is not null;
        InterruptedText = interrupted is null ? "" :
            $"Ein {Texts.Mode(interrupted.Header.Mode)} vom {interrupted.Header.StartedAt.ToLocalTime():g} wurde unterbrochen " +
            $"(zuletzt aktiv {interrupted.LastActivity.ToLocalTime():g}). {interrupted.FilesDone:N0} Dateien sind schon geprüft, {interrupted.Detections} Fund(e) bis dahin. " +
            "Beim Fortsetzen werden unveränderte, bereits geprüfte Dateien übersprungen.";
    }

    private async Task ExecuteAsync(Func<IProgress<ScanProgress>, CancellationToken, Task<(ScanReport Report, string ReportFile)?>> start)
    {
        Running = true;
        Results.Clear();
        Summary = "";
        ProgressKnown = false;
        ProgressText = "Scan wird vorbereitet …";
        _cts = new CancellationTokenSource();
        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                ProgressKnown = p.Fraction is not null;
                Progress = (p.Fraction ?? 0) * 100;
                _lastProgressText = $"{p.FilesCompleted:N0} von {p.FilesDiscovered:N0} Dateien" +
                    (p.Fraction is { } f ? $" ({f:P0})" : " – Gesamtzahl wird noch ermittelt") +
                    $", {p.FilesSkipped:N0} übersprungen, {p.Errors:N0} Fehler";
                ProgressText = Paused ? PausedText() : _lastProgressText;
            });

            if (await start(progress, _cts.Token) is not { } finished)
            {
                ProgressText = "Nichts zu scannen.";
                return;
            }

            var (report, file) = finished;

            var allowed = _host.AllowedHashes();
            foreach (var f in report.Files.Where(f => f.Verdict != Verdict.Clean).OrderBy(f => f.Verdict))
            {
                Results.Add(new ScanResultRow(f, f.Sha256 is not null && allowed.Contains(f.Sha256)));
            }

            foreach (var i in report.Issues)
            {
                Results.Add(new ScanResultRow(new FileScanResult(i.Path, null, null, Verdict.Error, SkipReason.None, [], i.Message, TimeSpan.Zero)));
            }

            var outcome = report.Outcome switch
            {
                ScanOutcome.Completed => "Scan abgeschlossen",
                ScanOutcome.Cancelled => "Scan abgebrochen – nicht alle Dateien wurden geprüft. Er kann später fortgesetzt werden",
                _ => "Scan wegen Engine-Fehler abgebrochen – nicht alle Dateien wurden geprüft. Er kann fortgesetzt werden, sobald clamd wieder läuft",
            };
            Summary = $"{outcome} ({report.Duration.TotalSeconds:F0} s). {report.FilesDiscovered:N0} Dateien gefunden, {report.CountOf(Verdict.Clean):N0} ohne Befund, " +
                      $"{report.CountOf(Verdict.Infected)} infiziert, {report.CountOf(Verdict.Suspicious)} verdächtig, {report.CountOf(Verdict.Incomplete)} unvollständig, " +
                      $"{report.CountOf(Verdict.Skipped)} übersprungen, {report.CountOf(Verdict.Error)} Fehler, {report.FilesNotProcessed} nicht bearbeitet. Bericht: {file}";
            ProgressKnown = report.Outcome == ScanOutcome.Completed;
            ProgressText = outcome;
        }
        finally
        {
            Running = false;
            Paused = false;
            _lastProgressText = "";
            _cts.Dispose();
            _cts = null;
            RefreshInterrupted();
            await _onFinished();
        }
    }

    internal void TogglePause()
    {
        if (!Running)
        {
            return;
        }

        if (Paused)
        {
            _host.ScanPause.Resume();
            Paused = false;
            ProgressText = _lastProgressText.Length > 0 ? _lastProgressText : "Scan läuft weiter …";
        }
        else
        {
            _host.ScanPause.Pause();
            Paused = true;
            ProgressText = PausedText();
        }
    }

    private string PausedText() =>
        $"Pausiert{(_lastProgressText.Length > 0 ? $" bei {_lastProgressText}" : "")}. Dateien, die gerade geprüft werden, laufen noch zu Ende. " +
        "„Weiter“ setzt den Scan fort; auch nach dem Schließen von UScan oder einem Neustart kann er später fortgesetzt werden.";

    private async Task QuarantineSelectedAsync()
    {
        var rows = Results.Where(r => r.Selected && r.CanQuarantine).ToArray();
        if (!_dialogs.Confirm("In Quarantäne verschieben",
                $"{rows.Length} Datei(en) werden verschlüsselt in die Quarantäne verschoben und am Originalort entfernt. Sie können später wiederhergestellt werden.\n\n" +
                string.Join("\n", rows.Select(r => r.Path))))
        {
            return;
        }

        foreach (var r in rows)
        {
            var engineId = r.Result.EngineResults.FirstOrDefault(e => e.Verdict == r.Result.Verdict)?.EngineId ?? "?";
            var q = await _host.Quarantine.QuarantineAsync(r.Path, r.Result.DetectionName ?? r.VerdictText, engineId, r.Result.Sha256, false, CancellationToken.None);
            if (!q.Success && q.Message.StartsWith("Protected file", StringComparison.Ordinal) &&
                _dialogs.Confirm("Geschützte Datei", $"{r.Path}\n\n{q.Message}\n\nNur fortfahren, wenn Sie Administrator sind und den Fund geprüft haben. Trotzdem verschieben?", dangerous: true))
            {
                q = await _host.Quarantine.QuarantineAsync(r.Path, r.Result.DetectionName ?? r.VerdictText, engineId, r.Result.Sha256, true, CancellationToken.None);
            }

            r.Action = q.Success ? "In Quarantäne" : $"Nicht verschoben: {q.Message}";
            r.Selected = false;
        }

        await _onFinished();
    }
}
