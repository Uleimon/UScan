using System.Runtime.Versioning;
using UScan.Core.Inventory;
using UScan.Windows.Authenticode;
using UScan.Windows.Inventory;

namespace UScan.Windows.Tests;

/// <summary>
/// Run against the real Windows APIs. On other operating systems every test reports
/// "skipped" (never "passed"), so a Linux run cannot be mistaken for Windows coverage.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("uscan-win-").FullName;

    public AuthenticodeTests()
    {
        WindowsOnly.Require();
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string SignedExe()
    {
        // The .NET host is shipped with an embedded Microsoft Authenticode signature.
        var root = Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? @"C:\Program Files\dotnet";
        var exe = Path.Combine(root, "dotnet.exe");
        Assert.True(File.Exists(exe), $"dotnet.exe not found at {exe}");
        return exe;
    }

    [Fact]
    public void Embedded_signature_is_valid_with_signer()
    {
        var r = new AuthenticodeVerifier().Verify(SignedExe());
        Assert.Equal(SignatureStatus.Valid, r.Status);
        // The .NET host certificate's simple name is ".NET" (observed on the CI runner); only require a signer name.
        Assert.False(string.IsNullOrWhiteSpace(r.Signer));
    }

    [Fact]
    public void System_file_is_trusted_via_embedded_or_catalog_signature()
    {
        var r = new AuthenticodeVerifier().Verify(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        Assert.True(r.IsTrusted, $"{r.Status}: {r.Detail}");
    }

    [Fact]
    public void Plain_file_is_not_signed()
    {
        var path = Path.Combine(_dir, "plain.exe");
        File.WriteAllText(path, "not a real executable");
        Assert.Equal(SignatureStatus.NotSigned, new AuthenticodeVerifier().Verify(path).Status);
    }

    [Fact]
    public void Modified_signed_file_is_invalid()
    {
        var copy = Path.Combine(_dir, "tampered.exe");
        File.Copy(SignedExe(), copy);
        var bytes = File.ReadAllBytes(copy);
        bytes[bytes.Length / 3] ^= 0xFF; // inside the signed image, away from headers and the signature blob
        File.WriteAllBytes(copy, bytes);

        var r = new AuthenticodeVerifier().Verify(copy);
        Assert.Equal(SignatureStatus.Invalid, r.Status);
        Assert.False(r.IsTrusted);
    }

    [Fact]
    public void Missing_file_is_an_error_not_a_crash()
    {
        var r = new AuthenticodeVerifier().Verify(Path.Combine(_dir, "nope.exe"));
        Assert.False(r.IsTrusted);
    }
}

[SupportedOSPlatform("windows")]
public sealed class InventorySourceTests
{
    public InventorySourceTests()
    {
        WindowsOnly.Require();
    }

    private static InventoryEntryFactory Factory() => new(new CommandLineResolver(), new AuthenticodeVerifier());

    [Fact]
    public void Services_include_well_known_trusted_service()
    {
        var errors = new List<string>();
        var entries = new ServiceSource(Factory()).Collect(errors).ToList();

        var eventLog = Assert.Single(entries, e => e.Name.Equals("EventLog", StringComparison.OrdinalIgnoreCase));
        Assert.True(eventLog.FileExists);
        Assert.NotNull(eventLog.Sha256);
        Assert.True(eventLog.Signature!.IsTrusted, $"{eventLog.ImagePath}: {eventLog.Signature.Status} {eventLog.Signature.Detail}");
        Assert.True(entries.Count > 50);
    }

    [Fact]
    public void Scheduled_tasks_are_enumerated()
    {
        var errors = new List<string>();
        var entries = new ScheduledTaskSource(Factory()).Collect(errors).ToList();
        Assert.NotEmpty(entries);
        Assert.Contains(entries, e => e.Location.StartsWith(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Registry_and_startup_sources_run_without_errors()
    {
        var snap = new InventoryCollector([new RegistryAutostartSource(Factory()), new StartupFolderSource(Factory())]).Collect();
        Assert.Empty(snap.Errors);
        Assert.Contains(snap.Entries, e => e.Kind == InventoryKind.WinlogonValue && e.Name == "Userinit");
        Assert.All(snap.Entries.Where(e => e.Kind == InventoryKind.WinlogonValue), e => Assert.DoesNotContain(e.Observations, o => o.Contains("Differs", StringComparison.Ordinal)));
    }
}

internal static class WindowsOnly
{
    public static void Require()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Requires Windows.");
        }
    }
}

/// <summary>False-positive measurement on the real Windows installation of the CI runner.</summary>
[SupportedOSPlatform("windows")]
public sealed class HeuristicFalsePositiveTests
{
    public HeuristicFalsePositiveTests()
    {
        WindowsOnly.Require();
    }

    [Fact]
    public void System32_executables_are_not_flagged()
    {
        var analyzer = new UScan.Core.Heuristics.PeAnalyzer(new AuthenticodeVerifier());
        var files = Directory.EnumerateFiles(Environment.SystemDirectory, "*.exe").Take(500).ToArray();
        Assert.True(files.Length > 100);
        var flagged = new List<string>();
        foreach (var f in files)
        {
            try
            {
                using var s = File.OpenRead(f);
                var r = analyzer.Analyze(f, s);
                if (r.Suspicious)
                {
                    flagged.Add($"{f}: {r.Explain()}");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        Assert.True(flagged.Count == 0, string.Join("\n", flagged));
    }

    [Fact]
    public void Windows_scripts_are_not_flagged()
    {
        var analyzer = new UScan.Core.Heuristics.ScriptAnalyzer();
        var files = new[] { "*.vbs", "*.cmd", "*.bat", "*.js", "*.ps1" }
            .SelectMany(p => Directory.EnumerateFiles(Environment.SystemDirectory, p)).ToArray();
        var flagged = new List<string>();
        foreach (var f in files)
        {
            using var s = File.OpenRead(f);
            var r = analyzer.Analyze(f, s);
            if (r.Suspicious)
            {
                flagged.Add($"{f}: {r.Explain()}");
            }
        }

        Assert.True(flagged.Count == 0, string.Join("\n", flagged));
    }
}

[SupportedOSPlatform("windows")]
public sealed class DefenderTests
{
    public DefenderTests()
    {
        WindowsOnly.Require();
    }

    [Fact]
    public void Interpret_requires_threat_line_for_detection()
    {
        var hit = UScan.Windows.Defender.DefenderEngine.Interpret(2, "Scan starting...\r\nScan finished.\r\nScanning C:\\x found 1 threats.\r\nThreat                  : Virus:DOS/EICAR_Test_File\r\n");
        Assert.Equal(UScan.Core.Model.Verdict.Infected, hit.Verdict);
        Assert.Equal("Virus:DOS/EICAR_Test_File", hit.DetectionName);

        var error = UScan.Windows.Defender.DefenderEngine.Interpret(2, "CmdTool: Failed with hr = 0x800106BA. The service is not running.");
        Assert.Equal(UScan.Core.Model.Verdict.Error, error.Verdict);

        Assert.Equal(UScan.Core.Model.Verdict.Clean, UScan.Windows.Defender.DefenderEngine.Interpret(0, "Scanning C:\\x found no threats.").Verdict);
    }

    [Fact]
    public async Task Defender_detects_eicar_when_available()
    {
        var engine = UScan.Windows.Defender.DefenderEngine.TryCreate();
        if (engine is null)
        {
            Assert.Skip("MpCmdRun.exe not present.");
        }

        var status = UScan.Windows.Defender.DefenderStatusProvider.Query();
        if (status.AntivirusEnabled != true)
        {
            Assert.Skip($"Defender antivirus not enabled on this machine ({status.Error ?? "AntivirusEnabled=false"}).");
        }

        var dir = Directory.CreateTempSubdirectory("uscan-def-").FullName;
        var file = Path.Combine(dir, "eicar.com");
        File.WriteAllText(file, string.Concat(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS", "-TEST-FILE!$H+H*"));
        if (!File.Exists(file))
        {
            Assert.Skip("Real-time protection removed the EICAR file immediately.");
        }

        var r = await engine.ScanFileAsync(file, TestContext.Current.CancellationToken);
        Assert.True(r.Verdict == UScan.Core.Model.Verdict.Infected, $"{r.Verdict}: {r.Detail}");
        Assert.Contains("EICAR", r.DetectionName, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Status_query_does_not_throw()
    {
        var s = UScan.Windows.Defender.DefenderStatusProvider.Query();
        Assert.True(s.Available || s.Error is not null);
    }
}
