using System.Runtime.InteropServices;

namespace UScan.Windows;

/// <summary>
/// Process background mode (SetPriorityClass with PROCESS_MODE_BACKGROUND_BEGIN): low CPU, disk I/O
/// and memory priority for this process. clamd only scans what UScan reads and sends it, so
/// throttling UScan's reads also keeps clamd's temporary files from saturating the disk.
/// Reference-counted, because a manual scan and a monitor re-scan can overlap.
/// </summary>
internal static class BackgroundMode
{
    private const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    private const uint PROCESS_MODE_BACKGROUND_END = 0x00200000;

    private static readonly Lock Gate = new();
    private static int _users;

    /// <summary>Whether the process is currently in background mode (for tests and diagnostics).</summary>
    public static bool Active { get; private set; }

    public static IDisposable? Enter()
    {
        lock (Gate)
        {
            if (_users == 0)
            {
                if (!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN))
                {
                    return null;
                }

                Active = true;
            }

            _users++;
            return new Lease();
        }
    }

    private static void Leave()
    {
        lock (Gate)
        {
            if (--_users == 0)
            {
                SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END);
                Active = false;
            }
        }
    }

    private sealed class Lease : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Leave();
            }
        }
    }

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetPriorityClass(IntPtr process, uint priorityClass);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();
}
