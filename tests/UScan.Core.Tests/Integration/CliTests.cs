using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Integration;

/// <summary>Runs the real uscan command line program against a private clamd (end-to-end).</summary>
[Trait("Category", "Integration")]
public sealed partial class CliTests(ClamdFixture clamd) : IClassFixture<ClamdFixture>, IDisposable
{
    private readonly TempDir _data = new();
    private readonly TempDir _files = new();

    public void Dispose()
    {
        _data.Dispose();
        _files.Dispose();
    }

    private static string CliDll()
    {
        // Test output: <repo>/tests/UScan.Core.Tests/bin/<Configuration>/net10.0/
        var testBin = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        var configuration = testBin.Parent!.Name;
        var repo = testBin.Parent.Parent!.Parent!.Parent!.Parent!.FullName;
        var dll = Path.Combine(repo, "src", "UScan.Cli", "bin", configuration, "net10.0", "uscan.dll");
        Assert.True(File.Exists(dll), $"CLI not built: {dll}");
        return dll;
    }

    private async Task<(int Exit, string Output)> Run(params string[] args) => await RunWithPort(clamd.Port, args);

    private async Task<(int Exit, string Output)> RunWithPort(int port, params string[] args)
    {
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(CliDll());
        foreach (var a in args.Concat(["--data", _data.Path, "--port", port.ToString(CultureInfo.InvariantCulture)]))
        {
            psi.ArgumentList.Add(a);
        }

        using var p = Process.Start(psi)!;
        p.StandardInput.Close();
        var ct = TestContext.Current.CancellationToken;
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromMinutes(2), ct);
        return (p.ExitCode, await stdout + await stderr);
    }

    private void SkipIfUnavailable()
    {
        if (clamd.SkipReason is { } reason)
        {
            Assert.Skip(reason);
        }
    }

    [Fact]
    public async Task Scan_detect_quarantine_restore_cycle()
    {
        SkipIfUnavailable();
        var eicar = _files.Write("dl/eicar.com", TestFiles.Eicar);
        _files.Write("dl/readme.txt", "harmless");

        var scan = await Run("scan", _files.Path);
        Assert.Equal(1, scan.Exit);
        Assert.Contains("INFIZIERT", scan.Output, StringComparison.Ordinal);
        Assert.Contains("UScan.Test.EICAR", scan.Output, StringComparison.Ordinal);
        Assert.Contains("1 infiziert", scan.Output, StringComparison.Ordinal);

        var status = await Run("status");
        Assert.Equal(1, status.Exit);
        Assert.Contains("Offene Funde:      1", status.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Geschützt", status.Output, StringComparison.Ordinal);

        // Without --yes and without interactive input nothing is moved.
        var refused = await Run("scan", _files.Path, "--quarantine");
        Assert.Contains("Bestätigung erforderlich", refused.Output, StringComparison.Ordinal);
        Assert.True(File.Exists(eicar));

        var quarantined = await Run("scan", _files.Path, "--quarantine", "--yes");
        Assert.Contains("File moved to quarantine.", quarantined.Output, StringComparison.Ordinal);
        Assert.False(File.Exists(eicar));

        var list = await Run("quarantine", "list");
        var id = IdPattern().Match(list.Output).Value;
        Assert.NotEmpty(id);
        Assert.Equal(0, (await Run("quarantine", "verify", id)).Exit);

        var statusAfter = await Run("status");
        Assert.Contains("Offene Funde:      0", statusAfter.Output, StringComparison.Ordinal);

        // Restore re-scans: still detected, so it is refused unless forced.
        var restoreRefused = await Run("quarantine", "restore", id, "--yes");
        Assert.Equal(2, restoreRefused.Exit);
        Assert.False(File.Exists(eicar));

        var restored = await Run("quarantine", "restore", id, "--yes", "--force");
        Assert.Equal(0, restored.Exit);
        Assert.True(File.Exists(eicar));

        var log = await Run("log");
        Assert.Contains("quarantine", log.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unreachable_engine_and_usage_errors_have_distinct_exit_codes()
    {
        SkipIfUnavailable();
        _files.Write("a.txt", "x");
        var closedPort = FreePort();
        var scan = await RunWithPort(closedPort, "scan", _files.Path);
        Assert.Equal(3, scan.Exit);

        var status = await RunWithPort(closedPort, "status");
        Assert.Equal(3, status.Exit);
        Assert.Contains("NICHT erreichbar", status.Output, StringComparison.Ordinal);
        Assert.Contains("Schutz eingeschränkt", status.Output, StringComparison.Ordinal);

        Assert.Equal(64, (await Run("scan", "--bogus")).Exit);
        Assert.Equal(64, (await Run("frobnicate")).Exit);
    }

    [Fact]
    public async Task Clean_folder_scan_succeeds()
    {
        SkipIfUnavailable();
        _files.Write("a.txt", "hello");
        _files.Write("b/c.txt", "world");
        var scan = await Run("scan", _files.Path);
        Assert.Equal(0, scan.Exit);
        Assert.Contains("2 gefunden, 2 ohne Befund", scan.Output, StringComparison.Ordinal);
    }

    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [GeneratedRegex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")]
    private static partial Regex IdPattern();
}
