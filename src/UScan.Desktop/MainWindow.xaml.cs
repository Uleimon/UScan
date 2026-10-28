using System.Windows;
using UScan.Desktop.ViewModels;

namespace UScan.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private async void ToggleTheme(object sender, RoutedEventArgs e)
    {
        App.ApplyTheme(!App.IsDark);
        // The status banner colour comes through a converter; re-read it for the new theme.
        if (DataContext is MainViewModel vm)
        {
            await vm.Dashboard.RefreshAsync();
        }
    }
}
