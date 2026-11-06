namespace UScan.Core.Scanning;

/// <summary>
/// Lets the user pause a running scan. While paused, no new file is sent to the engine; files that
/// are already being scanned finish first. The folder walk stops on its own once its queue is full.
/// </summary>
public sealed class ScanPauseGate
{
    private readonly Lock _gate = new();
    private TaskCompletionSource? _paused;

    public event EventHandler? Changed;

    public bool IsPaused
    {
        get
        {
            lock (_gate)
            {
                return _paused is not null;
            }
        }
    }

    public void Pause()
    {
        lock (_gate)
        {
            if (_paused is not null)
            {
                return;
            }

            _paused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Resume()
    {
        TaskCompletionSource? paused;
        lock (_gate)
        {
            paused = _paused;
            _paused = null;
        }

        if (paused is not null)
        {
            paused.TrySetResult();
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Returns at once when not paused, otherwise when resumed or cancelled.</summary>
    public Task WaitAsync(CancellationToken ct)
    {
        Task wait;
        lock (_gate)
        {
            if (_paused is null)
            {
                return Task.CompletedTask;
            }

            wait = _paused.Task;
        }

        return wait.WaitAsync(ct);
    }
}
