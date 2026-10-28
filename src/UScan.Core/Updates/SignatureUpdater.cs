using System.Diagnostics;
using UScan.Core.Storage;

namespace UScan.Core.Updates;

public sealed record ProcessResult(int ExitCode, string Output, bool TimedOut);

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct);
}

/// <summary>Runs a process without a shell; arguments are passed as a list so they cannot be re-interpreted.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in arguments)
        {
            psi.ArgumentList.Add(a);
        }

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"{executable} could not be started.");
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            p.Kill(entireProcessTree: true);
            return new ProcessResult(-1, "", TimedOut: true);
        }

        return new ProcessResult(p.ExitCode, await stdout.ConfigureAwait(false) + await stderr.ConfigureAwait(false), false);
    }
}

public sealed record SignatureUpdateResult(bool Success, bool UpToDate, string Summary, string Output);

/// <summary>
/// Updates the ClamAV databases with the official <c>freshclam</c> tool, which downloads from the
/// ClamAV mirrors and verifies the digital signature of every database file before replacing it.
/// UScan does not parse or modify database files itself.
/// </summary>
public sealed class FreshclamUpdater(string freshclamPath, string? configFile, IProcessRunner? runner = null, JsonLinesEventLog? log = null, TimeProvider? time = null)
{
    private readonly IProcessRunner _runner = runner ?? new ProcessRunner();

    public async Task<SignatureUpdateResult> UpdateAsync(CancellationToken ct = default)
    {
        if (!File.Exists(freshclamPath))
        {
            return Log(new SignatureUpdateResult(false, false, $"freshclam not found at '{freshclamPath}'.", ""));
        }

        var args = new List<string> { "--stdout", "--no-warnings" };
        if (configFile is not null)
        {
            args.Add($"--config-file={configFile}");
        }

        ProcessResult r;
        try
        {
            r = await _runner.RunAsync(freshclamPath, args, TimeSpan.FromMinutes(15), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return Log(new SignatureUpdateResult(false, false, $"freshclam could not be started: {ex.Message}", ""));
        }

        if (r.TimedOut)
        {
            return Log(new SignatureUpdateResult(false, false, "freshclam did not finish within 15 minutes.", r.Output));
        }

        // Documented in freshclam(1): 0 = "Database is up-to-date or successfully updated"; other codes are errors.
        if (r.ExitCode == 0)
        {
            var updated = r.Output.Contains("updated (version", StringComparison.OrdinalIgnoreCase);
            return Log(new SignatureUpdateResult(true, !updated, updated ? "Signatures updated." : "Signatures are up to date.", r.Output));
        }

        return Log(new SignatureUpdateResult(false, false, $"freshclam failed: {Describe(r.ExitCode)} (exit code {r.ExitCode}).", r.Output));
    }

    /// <summary>Return codes as documented in freshclam(1).</summary>
    internal static string Describe(int code) => code switch
    {
        40 => "unknown option",
        50 => "cannot change directory",
        51 => "cannot check MD5 sum",
        52 => "network connection problem",
        53 => "cannot unlink file",
        54 => "MD5 or digital signature verification error – downloaded data was rejected",
        55 => "error reading file",
        56 => "configuration file error",
        57 => "cannot create new file",
        58 => "cannot read database from remote server",
        59 => "mirrors are not fully synchronized, try again later",
        60 => "cannot get information about the 'clamav' user",
        61 => "cannot drop privileges",
        62 => "cannot initialize logger",
        _ => "unexpected error",
    };

    private SignatureUpdateResult Log(SignatureUpdateResult r)
    {
        log?.Append(new SecurityEvent((time ?? TimeProvider.System).GetUtcNow(), r.Success ? EventSeverity.Info : EventSeverity.Error, "update", r.Summary));
        return r;
    }
}
