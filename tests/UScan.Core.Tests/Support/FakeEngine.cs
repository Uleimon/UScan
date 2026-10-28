using UScan.Core.Engines;
using UScan.Core.Model;

namespace UScan.Core.Tests.Support;

/// <summary>Deterministic engine for orchestration tests. Flags content that contains EICAR.</summary>
internal sealed class FakeEngine : IScanEngine
{
    private int _scans;

    public string Id => "fake";
    public long MaxStreamBytes { get; init; } = 1024 * 1024;
    public TimeSpan DelayPerFile { get; init; }
    public int FailAfterScans { get; init; } = int.MaxValue;
    public bool Unavailable { get; init; }
    public int Scans => _scans;

    public Task<EngineInfo> GetInfoAsync(CancellationToken cancellationToken) =>
        Unavailable
            ? throw new EngineUnavailableException("fake engine offline")
            : Task.FromResult(new EngineInfo(Id, "1.0", 1, DateTimeOffset.UtcNow));

    public async Task<EngineResult> ScanAsync(Stream content, CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref _scans) > FailAfterScans)
        {
            throw new EngineUnavailableException("fake engine crashed");
        }

        if (DelayPerFile > TimeSpan.Zero)
        {
            await Task.Delay(DelayPerFile, cancellationToken);
        }

        using var ms = new MemoryStream();
        await content.CopyToAsync(ms, cancellationToken);
        var found = ms.ToArray().AsSpan().IndexOf(TestFiles.Eicar) >= 0;
        return found
            ? new EngineResult(Verdict.Infected, Id, "Fake.EICAR", null)
            : new EngineResult(Verdict.Clean, Id, null, null);
    }
}
