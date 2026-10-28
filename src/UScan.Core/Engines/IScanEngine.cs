using UScan.Core.Model;

namespace UScan.Core.Engines;

/// <summary>
/// A detection engine that classifies a byte stream. Implementations must read the
/// stream to its end or throw; they must never report <see cref="Verdict.Clean"/> for
/// content they did not fully inspect.
/// </summary>
public interface IScanEngine
{
    string Id { get; }

    /// <summary>Largest stream the engine accepts. Larger files are reported as skipped, not clean.</summary>
    long MaxStreamBytes { get; }

    Task<EngineInfo> GetInfoAsync(CancellationToken cancellationToken);

    Task<EngineResult> ScanAsync(Stream content, CancellationToken cancellationToken);
}

/// <summary>Raised when the engine itself is unavailable or misbehaves (as opposed to a per-file problem).</summary>
public sealed class EngineUnavailableException : Exception
{
    public EngineUnavailableException(string message) : base(message) { }
    public EngineUnavailableException(string message, Exception inner) : base(message, inner) { }
    public EngineUnavailableException() { }
}

/// <summary>An engine that scans files by path (e.g. an external command-line scanner used as second opinion).</summary>
public interface IFileScanEngine
{
    string Id { get; }

    Task<EngineResult> ScanFileAsync(string path, CancellationToken cancellationToken);
}
