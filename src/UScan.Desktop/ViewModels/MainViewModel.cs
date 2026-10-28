using UScan.Core.App;

namespace UScan.Desktop.ViewModels;

internal sealed class MainViewModel : ObservableObject
{
    private object _page;

    public MainViewModel(UScanHost host, IDialogs dialogs)
    {
        Host = host;
        Dashboard = new DashboardViewModel(host, () => Scan?.Running == true);
        Scan = new ScanViewModel(host, dialogs, RefreshAllAsync);
        Quarantine = new QuarantineViewModel(host, dialogs, () => Dashboard.RefreshAsync());
        Inventory = new InventoryViewModel(host);
        Monitor = new MonitorViewModel(host, () => Dashboard.RefreshAsync());
        Log = new LogViewModel(host);
        _page = Dashboard;
        NavigateCommand = new RelayCommand(p =>
        {
            Page = p switch
            {
                "scan" => Scan,
                "quarantine" => Quarantine,
                "inventory" => Inventory,
                "monitor" => Monitor,
                "log" => Log,
                "about" => (object)this,
                _ => Dashboard,
            };
            if (Page == Quarantine)
            {
                Quarantine.Refresh();
            }
            else if (Page == Log)
            {
                Log.Refresh();
            }
        });
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
