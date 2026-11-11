using UScan.Core.App;

namespace UScan.Desktop.ViewModels;

internal sealed class MainViewModel : ObservableObject
{
    private object _page;
    private string _pageKey;

    public MainViewModel(UScanHost host, IDialogs dialogs)
    {
        Host = host;
        Dashboard = new DashboardViewModel(host, () => Scan?.Running == true, dialogs);
        Scan = new ScanViewModel(host, dialogs, RefreshAllAsync);
        Quarantine = new QuarantineViewModel(host, dialogs, () => Dashboard.RefreshAsync());
        Inventory = new InventoryViewModel(host);
        Monitor = new MonitorViewModel(host, () => Dashboard.RefreshAsync());
        Log = new LogViewModel(host);
        // An interrupted scan is offered for continuing right away.
        _page = Scan.HasInterrupted ? Scan : Dashboard;
        _pageKey = Scan.HasInterrupted ? "scan" : "dashboard";
        NavigateCommand = new RelayCommand(p => Navigate(p as string ?? "dashboard"));
    }

    /// <summary>The page shown, by name; the sidebar binds to it so the active entry stays highlighted.</summary>
    public string PageKey
    {
        get => _pageKey;
        set => Navigate(value);
    }

    private void Navigate(string key)
    {
        Page = key switch
        {
            "scan" => Scan,
            "quarantine" => Quarantine,
            "inventory" => Inventory,
            "monitor" => Monitor,
            "log" => Log,
            "about" => (object)this,
            _ => Dashboard,
        };
        Set(ref _pageKey, key, nameof(PageKey));
        if (Page == Quarantine)
        {
            Quarantine.Refresh();
        }
        else if (Page == Log)
        {
            Log.Refresh();
        }
    }

    public UScanHost Host { get; }
    public DashboardViewModel Dashboard { get; }
    public ScanViewModel Scan { get; }
    public QuarantineViewModel Quarantine { get; }
    public InventoryViewModel Inventory { get; }
    public MonitorViewModel Monitor { get; }
    public LogViewModel Log { get; }
    public RelayCommand NavigateCommand { get; }

    public object Page { get => _page; private set => Set(ref _page, value); }

    public string Version => typeof(UScanHost).Assembly.GetName().Version?.ToString(3) ?? "?";
    public string DataFolder => Host.Paths.Root;
    public string SettingsFile => Host.Paths.Settings;

    private async Task RefreshAllAsync()
    {
        Quarantine.Refresh();
        await Dashboard.RefreshAsync();
    }
}
