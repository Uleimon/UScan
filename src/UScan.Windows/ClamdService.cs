using System.Diagnostics;
using System.Runtime.Versioning;
using UScan.Core.App;

namespace UScan.Windows;

/// <summary>
/// The clamd Windows service and the ClamAV copy the UScan setup installs next to UScan.exe.
/// The setup allows signed-in users to start the service, so UScan can start it without admin rights.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ClamdService
{
    public const string ServiceName = "clamd";
    public const string ManagedMarker = "uscan-managed.txt";

    private static readonly Lock Gate = new();
    private static long _lastAttempt = long.MinValue;

    public static ManagedClamAV? FindManaged(string programDirectory)
    {
        var dir = Path.Combine(programDirectory, "ClamAV");
        var freshclam = Path.Combine(dir, "freshclam.exe");
        var config = Path.Combine(dir, "freshclam.conf");
        return File.Exists(Path.Combine(dir, ManagedMarker)) && File.Exists(freshclam) && File.Exists(config)
            ? new ManagedClamAV(dir, freshclam, config)
            : null;
    }

    /// <summary>Starts the service if it exists and is stopped; at most one attempt per minute.</summary>
    public static bool TryStart()
    {
        lock (Gate)
        {
            var now = Environment.TickCount64;
            if (_lastAttempt != long.MinValue && now - _lastAttempt < 60_000)
            {
                return false;
            }

            _lastAttempt = now;
        }

        // "sc query" prints "STATE : 1  STOPPED"; the number is the same in every Windows language.
        if (Run("query") is not { } query || !query.Split('\n').Any(l => l.Contains("STATE", StringComparison.Ordinal) && l.Contains(": 1 ", StringComparison.Ordinal)))
        {
            return false; // not installed, already running or starting, or sc failed
        }

        return Run("start") is not null;
    }

    private static string? Run(string verb)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), $"{verb} {ServiceName}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p is null)
            {
                return null;
            }

            var output = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(10_000))
            {
                p.Kill();
                return null;
            }

            return p.ExitCode == 0 ? output : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}
