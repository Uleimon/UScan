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
    private bool _showingError;
    private bool _selfTest;

    internal static bool IsDark { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _selfTest = e.Args.Contains("--ui-selftest");
        DispatcherUnhandledException += (_, args) =>
        {
            // Show the real error instead of crashing silently or pretending everything is fine.
            // The message box pumps messages; if the same error recurs while it is open (e.g. in
            // layout), end the application instead of stacking dialogs until the stack overflows.
            if (_selfTest)
            {
                Console.Error.WriteLine(args.Exception);
                args.Handled = true;
                Shutdown(3);
                return;
            }

            if (_showingError)
            {
                args.Handled = false;
                return;
            }

            _showingError = true;
            MessageBox.Show(args.Exception.ToString(), "UScan – unerwarteter Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            _showingError = false;
            args.Handled = true;
        };

        ApplyTheme(SystemUsesDarkTheme());
        var host = new UScanHost(AppPaths.Default, new WindowsPlatformServices());
        _main = new MainViewModel(host, new WpfDialogs());
        var window = new MainWindow { DataContext = _main };
        window.Show();
        _ = _main.Dashboard.RefreshAsync();
        if (_selfTest)
        {
            _ = RunSelfTestAsync(window, _main);
        }
    }

    /// <summary>
    /// For CI: shows every page once (forcing layout and bindings) and exits with 0.
    /// Any exception ends the process with code 3 and is written to stderr.
    /// </summary>
    private async Task RunSelfTestAsync(Window window, MainViewModel main)
    {
        foreach (var page in new[] { "scan", "quarantine", "inventory", "monitor", "log", "about", "dashboard" })
        {
            main.NavigateCommand.Execute(page);
            window.UpdateLayout();
            await Task.Delay(700);
            Console.Out.WriteLine($"page ok: {page}");
        }

        ApplyTheme(!IsDark);
        window.UpdateLayout();
        await Task.Delay(700);
        Console.Out.WriteLine("theme switch ok");
        Shutdown(0);
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
