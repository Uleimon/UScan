using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using UScan.Core.Model;

namespace UScan.Windows.Defender;

/// <summary>
/// Second, independent opinion from Microsoft Defender Antivirus via its documented command-line
/// tool: <c>MpCmdRun.exe -Scan -ScanType 3 -File &lt;path&gt; -DisableRemediation</c>.
/// With -DisableRemediation Defender reports detections in the output only and takes no action,
/// so UScan stays in control of quarantine. Return code 2 means "malware found OR scanning error",
/// therefore the output is parsed and an unexplained 2 is reported as an error, not as a detection.
/// Reference: learn.microsoft.com/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class DefenderEngine : UScan.Core.Engines.IFileScanEngine
{
    public const string EngineId = "defender";

    public string Id => EngineId;

    private readonly string _mpCmdRun;
    private readonly TimeSpan _timeout;

    private DefenderEngine(string mpCmdRun, TimeSpan timeout)
    {
        _mpCmdRun = mpCmdRun;
        _timeout = timeout;
    }

    public string ExecutablePath => _mpCmdRun;

    /// <returns>null if MpCmdRun.exe is not present (Defender not installed).</returns>
    public static DefenderEngine? TryCreate(TimeSpan? timeout = null)
    {
        var path = Locate();
        return path is null ? null : new DefenderEngine(path, timeout ?? TimeSpan.FromMinutes(10));
    }

    /// <summary>The newest platform folder wins, as documented by Microsoft.</summary>
    internal static string? Locate()
    {
        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platform))
        {
            var newest = Directory.EnumerateDirectories(platform)
                .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                .Where(x => x.Version is not null && File.Exists(Path.Combine(x.Dir, "MpCmdRun.exe")))
                .OrderByDescending(x => x.Version)
                .Select(x => Path.Combine(x.Dir, "MpCmdRun.exe"))
                .FirstOrDefault();
            if (newest is not null)
            {
                return newest;
            }
        }

        var legacy = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        return File.Exists(legacy) ? legacy : null;
    }

    public async Task<EngineResult> ScanFileAsync(string path, CancellationToken cancellationToken)
    {
        var full = Path.GetFullPath(path);
        var info = new FileInfo(full);
        if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return new EngineResult(Verdict.Error, EngineId, null, "File missing or is a link; not passed to Defender.");
        }

        var psi = new ProcessStartInfo(_mpCmdRun)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        // ArgumentList quotes each argument; no shell is involved, so file names cannot inject options.
        foreach (var a in new[] { "-Scan", "-ScanType", "3", "-File", full, "-DisableRemediation" })
        {
            psi.ArgumentList.Add(a);
        }

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("MpCmdRun.exe could not be started.");
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return new EngineResult(Verdict.Error, EngineId, null, $"Defender scan exceeded {_timeout}.");
        }

        return Interpret(process.ExitCode, await stdout.ConfigureAwait(false) + await stderr.ConfigureAwait(false));
    }

    internal static EngineResult Interpret(int exitCode, string output)
    {
        var threats = ThreatLine().Matches(output).Select(m => m.Groups[1].Value.Trim()).Where(t => t.Length > 0).Distinct().ToArray();
        if (threats.Length > 0)
        {
            return new EngineResult(Verdict.Infected, EngineId, string.Join(", ", threats), Tail(output));
        }

        if (exitCode == 0)
        {
            return new EngineResult(Verdict.Clean, EngineId, null, Tail(output));
        }

        return new EngineResult(Verdict.Error, EngineId, null, $"MpCmdRun exit code {exitCode} without a reported threat (scan error): {Tail(output)}");
    }

    private static string Tail(string s)
    {
        s = s.Trim();
        return s.Length <= 600 ? s : "…" + s[^600..];
    }

    [GeneratedRegex(@"^\s*Threat\s*:\s*(.+?)\s*$", RegexOptions.Multiline, 500)]
    private static partial Regex ThreatLine();
}
