using System.Runtime.Versioning;
using System.Text;
using UScan.Core.App;
using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Status;
using UScan.Core.Storage;
using UScan.Desktop.ViewModels;

namespace UScan.Windows.Tests;

/// <summary>Checks that the desktop view models show real backend state and never a false green.</summary>
[SupportedOSPlatform("windows")]
public sealed class DesktopViewModelTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("uscan-ui-").FullName;

    public DesktopViewModelTests()
    {
        WindowsOnly.Require();
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class YesDialogs : IDialogs
    {
        public bool Confirm(string title, string message, bool dangerous = false) => true;
        public void Info(string title, string message) { }
        public string? PickFolder() => null;
    }

    private sealed class NoDialogs : IDialogs
    {
        public bool Confirm(string title, string message, bool dangerous = false) => false;
        public void Info(string title, string message) { }
        public string? PickFolder() => null;
    }

    private UScanHost Host() =>
        new(new AppPaths(Path.Combine(_dir, "data")), new WindowsPlatformServices(), new UScanSettings { ClamdPort = ClosedPort() });

    private static int ClosedPort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Theory]
    [InlineData(Verdict.Infected, false, "Serious", "DangerBrush")]
    [InlineData(Verdict.Suspicious, false, "Minor", "MinorBrush")]
    [InlineData(Verdict.Infected, true, "FalseAlarm", "InfoBrush")]
    [InlineData(Verdict.Suspicious, true, "FalseAlarm", "InfoBrush")]
    [InlineData(Verdict.Clean, false, "Ok", "OkBrush")]
    [InlineData(Verdict.Error, false, "Unchecked", "NeutralBrush")]
    [InlineData(Verdict.Skipped, true, "Unchecked", "NeutralBrush")]
    public void Findings_are_coloured_by_how_serious_they_are(Verdict verdict, bool allowed, string expected, string brush)
    {
        var row = new ScanResultRow(new FileScanResult("C:\\x.exe", null, null, verdict, SkipReason.None, [], null, TimeSpan.Zero), allowed);
        Assert.Equal(expected, row.Category.ToString());
        Assert.Equal(brush, row.CategoryBrushKey);
    }

    [Fact]
    public void Log_lines_are_coloured_and_only_findings_are_red()
    {
        var now = DateTimeOffset.Now;
        Assert.Equal(FindingCategory.Serious, new LogRow(new SecurityEvent(now, EventSeverity.Threat, "scan", "Infected: Win.Test")).Color);
        Assert.Equal(FindingCategory.Minor, new LogRow(new SecurityEvent(now, EventSeverity.Warning, "scan", "Suspicious: UScan.Heuristic.Score65")).Color);
        Assert.Equal(FindingCategory.FalseAlarm, new LogRow(new SecurityEvent(now, EventSeverity.Info, "scan", "Infected: Win.Test (allowed by user as false positive, same SHA-256)")).Color);
        Assert.Equal(FindingCategory.FalseAlarm, new LogRow(new SecurityEvent(now, EventSeverity.Warning, "allowlist", "User marked detection as allowed")).Color);
        Assert.Equal(FindingCategory.Ok, new LogRow(new SecurityEvent(now, EventSeverity.Info, "scan", "Full scan started (5 root(s)).")).Color);
    }

    [Fact]
    public async Task Dashboard_without_engine_is_not_green()
    {
        var vm = new DashboardViewModel(Host(), () => false);
        await vm.RefreshAsync();
        Assert.NotEqual(ProtectionState.Protected, vm.State);
        Assert.NotEqual("OkBrush", vm.StateBrushKey);
        Assert.Contains("NICHT erreichbar", vm.Engine, StringComparison.Ordinal);
        Assert.Contains(vm.Reasons, r => r.Contains("not reachable", StringComparison.Ordinal));
        Assert.Contains("Läuft nicht", vm.Monitor, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Open_detection_from_a_report_turns_the_dashboard_red()
    {
        var host = Host();
        var file = Path.Combine(_dir, "found.bin");
        await File.WriteAllTextAsync(file, "x", TestContext.Current.CancellationToken);
        host.Reports.Save(new ScanReport(Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, ScanOutcome.Completed, [_dir], null, 1,
            [new FileScanResult(file, 1, new string('0', 64), Verdict.Infected, SkipReason.None, [new EngineResult(Verdict.Infected, "clamav", "Test.Sig", null)], null, TimeSpan.Zero)], []));

        var vm = new DashboardViewModel(host, () => false);
        await vm.RefreshAsync();
        Assert.Equal(ProtectionState.ThreatFound, vm.State);
        Assert.Equal("DangerBrush", vm.StateBrushKey);
        Assert.Single(vm.OpenDetections);
    }

    [Fact]
    public async Task Open_detection_can_be_allowed_or_quarantined_from_the_dashboard()
    {
        var host = Host();
        var allowMe = Path.Combine(_dir, "allow.bin");
        var moveMe = Path.Combine(_dir, "move.bin");
        await File.WriteAllTextAsync(allowMe, "a", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(moveMe, "m", TestContext.Current.CancellationToken);
        static string Sha(string text) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        host.Reports.Save(new ScanReport(Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, ScanOutcome.Completed, [_dir], null, 2,
            [new FileScanResult(allowMe, 1, Sha("a"), Verdict.Infected, SkipReason.None, [new EngineResult(Verdict.Infected, "clamav", "Test.A", null)], null, TimeSpan.Zero),
             new FileScanResult(moveMe, 1, Sha("m"), Verdict.Infected, SkipReason.None, [new EngineResult(Verdict.Infected, "clamav", "Test.M", null)], null, TimeSpan.Zero)], []));

        var vm = new DashboardViewModel(host, () => false, new YesDialogs());
        await vm.RefreshAsync();
        Assert.Equal(2, vm.OpenDetections.Count);

        await vm.AllowDetectionAsync(vm.OpenDetections.Single(r => r.Detection.Path == allowMe));
        await vm.QuarantineDetectionAsync(vm.OpenDetections.Single(r => r.Detection.Path == moveMe));

        Assert.Empty(vm.OpenDetections);
        Assert.True(File.Exists(allowMe));
        Assert.False(File.Exists(moveMe));
        Assert.Single(host.Quarantine.List());
        Assert.NotEqual(ProtectionState.ThreatFound, vm.State);
    }

    [Fact]
    public async Task Scan_with_unreachable_engine_reports_abort_not_success()
    {
        var target = Path.Combine(_dir, "t");
        Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "a.txt"), "hello", Encoding.UTF8, TestContext.Current.CancellationToken);
        var refreshed = 0;
        // Without the start-up wait; waiting for clamd is covered in ScanRunnerTests.
        using var vm = new ScanViewModel(Host(), new NoDialogs(), () => { refreshed++; return Task.CompletedTask; }) { WaitForEngine = false };

        await vm.RunAsync(ScanMode.Custom, [target]);

        Assert.Contains("Engine-Fehler", vm.Summary, StringComparison.Ordinal);
        Assert.False(vm.ProgressKnown);
        Assert.False(vm.Running);
        Assert.Equal(1, refreshed);
    }

    [Fact]
    public async Task Interrupted_scan_is_offered_for_continuing_and_can_be_discarded()
    {
        var target = Path.Combine(_dir, "t2");
        Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "a.txt"), "hello", Encoding.UTF8, TestContext.Current.CancellationToken);
        var host = Host();
        using var vm = new ScanViewModel(host, new YesDialogs(), () => Task.CompletedTask) { WaitForEngine = false };
        Assert.False(vm.HasInterrupted);

        await vm.RunAsync(ScanMode.Custom, [target]); // engine unreachable: the scan stops and can be continued

        Assert.True(vm.HasInterrupted);
        Assert.Contains("unterbrochen", vm.InterruptedText, StringComparison.Ordinal);

        vm.DiscardCommand.Execute(null);
        Assert.False(vm.HasInterrupted);
        Assert.Null(host.InterruptedScan());
    }

    [Fact]
    public void On_access_query_returns_an_explained_state()
    {
        var r = new WindowsPlatformServices().QueryOnAccessProtection();
        Assert.False(string.IsNullOrWhiteSpace(r.Detail));
    }
}
