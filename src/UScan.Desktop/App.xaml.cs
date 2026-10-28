using System.Windows;
using Microsoft.Win32;
using UScan.Core.App;
using UScan.Core.Storage;
using UScan.Desktop.ViewModels;
using UScan.Windows;

namespace UScan.Desktop;

public partial class App : Application
{
    private MainViewModel? _main;

    internal static bool IsDark { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
        {
            // Show the real error instead of crashing silently or pretending everything is fine.
            MessageBox.Show(args.Exception.ToString(), "UScan – unerwarteter Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        ApplyTheme(SystemUsesDarkTheme());
        var host = new UScanHost(AppPaths.Default, new WindowsPlatformServices());
        _main = new MainViewModel(host, new WpfDialogs());
        var window = new MainWindow { DataContext = _main };
        window.Show();
        _ = _main.Dashboard.RefreshAsync();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _main?.Monitor.StopAsync().GetAwaiter().GetResult();
        base.OnExit(e);
    }

    internal static void ApplyTheme(bool dark)
    {
        IsDark = dark;
        var dictionaries = Current.Resources.MergedDictionaries;
        dictionaries[0] = new ResourceDictionary { Source = new Uri(dark ? "Themes/Dark.xaml" : "Themes/Light.xaml", UriKind.Relative) };
    }

    /// <summary>Follows the Windows app theme setting (Settings → Personalisation → Colours).</summary>
    private static bool SystemUsesDarkTheme()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
    }
}
