using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using UScan.Core.Engines.ClamAV;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Integration;

/// <summary>
/// Starts a private clamd instance on a random loopback port with a test-only signature
/// database (EICAR by MD5). No official signatures are needed, so these tests are
/// reproducible offline. Tests are skipped (and reported as skipped) when clamd is not installed.
/// Set USCAN_CLAMD to the clamd executable path to override discovery.
/// </summary>
public sealed class ClamdFixture : IAsyncLifetime
{
    public const long MaxFileSize = 10L * 1024 * 1024;
    public const long MaxScanSize = 50L * 1024 * 1024;
    public const int MaxFiles = 1000;
    public const int MaxRecursion = 5;
    public const long StreamMaxLength = 20L * 1024 * 1024;

    private Process? _process;
    private string? _workDir;

    public string? SkipReason { get; private set; }
    public int Port { get; private set; }

    public ArchiveLimits ArchiveLimits { get; } = new(MaxFileSize, MaxScanSize, MaxFiles, MaxCompressionRatio: 1000);

    public ClamdEngine CreateEngine() => new(new ClamdOptions { Port = Port, MaxStreamBytes = StreamMaxLength });

    public async ValueTask InitializeAsync()
    {
        var exe = FindClamd();
        if (exe is null)
        {
            SkipReason = "clamd not found (install ClamAV or set USCAN_CLAMD).";
            return;
        }

        _workDir = Directory.CreateTempSubdirectory("uscan-clamd-").FullName;
        var db = Directory.CreateDirectory(Path.Combine(_workDir, "db")).FullName;
        await File.WriteAllTextAsync(Path.Combine(db, "uscan-test.hdb"), $"{TestFiles.EicarMd5}:68:UScan.Test.EICAR\n");

        Port = FreePort();
        var conf = Path.Combine(_workDir, "clamd.conf");
        await File.WriteAllTextAsync(conf, string.Create(CultureInfo.InvariantCulture, $"""
            Foreground yes
            TCPSocket {Port}
            TCPAddr 127.0.0.1
            DatabaseDirectory {db}
            LogFile {Path.Combine(_workDir, "clamd.log")}
            StreamMaxLength {StreamMaxLength / (1024 * 1024)}M
            MaxFileSize {MaxFileSize / (1024 * 1024)}M
            MaxScanSize {MaxScanSize / (1024 * 1024)}M
            MaxFiles {MaxFiles}
            MaxRecursion {MaxRecursion}
            AlertExceedsMax yes
            AlertEncrypted yes
            """));

        _process = Process.Start(new ProcessStartInfo(exe, ["-c", conf])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("clamd failed to start");
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var engine = CreateEngine();
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (DateTime.UtcNow < deadline)
        {
            if (_process.HasExited)
            {
                throw new InvalidOperationException($"clamd exited with {_process.ExitCode}; see {_workDir}/clamd.log");
            }

            if (await engine.PingAsync(CancellationToken.None))
            {
                return;
            }

            await Task.Delay(200);
        }

        throw new TimeoutException("clamd did not become ready within 60 s.");
    }

    public async ValueTask DisposeAsync()
    {
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync();
        }

        _process?.Dispose();
        if (_workDir is not null)
        {
            Directory.Delete(_workDir, recursive: true);
        }
    }

    private static string? FindClamd()
    {
        var env = Environment.GetEnvironmentVariable("USCAN_CLAMD");
        if (!string.IsNullOrEmpty(env))
        {
            return File.Exists(env) ? env : null;
        }

        var names = OperatingSystem.IsWindows() ? new[] { "clamd.exe" } : ["clamd"];
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Concat(OperatingSystem.IsWindows() ? [@"C:\Program Files\ClamAV"] : ["/usr/sbin", "/usr/local/sbin"]);
        return dirs.SelectMany(d => names.Select(n => Path.Combine(d, n))).FirstOrDefault(File.Exists);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
