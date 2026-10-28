using UScan.Core.Model;
using UScan.Core.Status;
using Microsoft.Extensions.Time.Testing;

namespace UScan.Core.Tests.Unit;

public class StatusEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);
    private readonly StatusEvaluator _eval = new(TimeSpan.FromDays(3), new FakeTimeProvider(Now));

    private static StatusInputs Good() => new(
        EngineReachable: true,
        Engine: new EngineInfo("clamav", "1.5.4", 27800, Now.AddHours(-5)),
        ScanRunning: false,
        UnresolvedThreats: 0,
        PendingActions: 0,
        OnAccessProtectionActive: true,
        FileMonitorActive: true);

    [Fact]
    public void All_good_is_protected() =>
        Assert.Equal(ProtectionState.Protected, _eval.Evaluate(Good()).State);

    [Fact]
    public void Null_input_is_unknown() =>
        Assert.Equal(ProtectionState.Unknown, _eval.Evaluate(null).State);

    [Fact]
    public void Engine_down_is_never_protected() =>
        Assert.Equal(ProtectionState.ProtectionLimited, _eval.Evaluate(Good() with { EngineReachable = false }).State);

    [Fact]
    public void Old_signatures_require_update() =>
        Assert.Equal(ProtectionState.UpdateRequired,
            _eval.Evaluate(Good() with { Engine = Good().Engine! with { DatabaseTimestamp = Now.AddDays(-4) } }).State);

    [Fact]
    public void Unknown_signature_age_requires_update() =>
        Assert.Equal(ProtectionState.UpdateRequired,
            _eval.Evaluate(Good() with { Engine = Good().Engine! with { DatabaseTimestamp = null } }).State);

    [Fact]
    public void Missing_real_time_component_limits_protection()
    {
        var a = _eval.Evaluate(Good() with { OnAccessProtectionActive = null });
        Assert.Equal(ProtectionState.ProtectionLimited, a.State);
        Assert.Contains(a.Reasons, r => r.Contains("unknown", StringComparison.Ordinal));

        var b = _eval.Evaluate(Good() with { OnAccessProtectionActive = false });
        Assert.Contains(b.Reasons, r => r.Contains("cannot block", StringComparison.Ordinal));
    }

    [Fact]
    public void Threat_outranks_everything_else()
    {
        var a = _eval.Evaluate(Good() with { UnresolvedThreats = 1, EngineReachable = false, PendingActions = 2 });
        Assert.Equal(ProtectionState.ThreatFound, a.State);
        Assert.Equal(3, a.Reasons.Count);
    }

    [Fact]
    public void Scan_running_does_not_hide_problems()
    {
        Assert.Equal(ProtectionState.ScanRunning, _eval.Evaluate(Good() with { ScanRunning = true }).State);
        Assert.Equal(ProtectionState.ProtectionLimited, _eval.Evaluate(Good() with { ScanRunning = true, EngineReachable = false }).State);
    }

    [Fact]
    public void Protected_requires_every_input_to_be_good()
    {
        // Exhaustively flip each input to its bad value: none may yield Protected.
        var bad = new[]
        {
            Good() with { EngineReachable = false },
            Good() with { Engine = null },
            Good() with { Engine = Good().Engine! with { DatabaseTimestamp = null } },
            Good() with { Engine = Good().Engine! with { DatabaseTimestamp = Now.AddDays(-30) } },
            Good() with { UnresolvedThreats = 1 },
            Good() with { PendingActions = 1 },
            Good() with { OnAccessProtectionActive = false },
            Good() with { OnAccessProtectionActive = null },
            Good() with { FileMonitorActive = false },
            Good() with { FileMonitorActive = null },
        };
        Assert.All(bad, i => Assert.NotEqual(ProtectionState.Protected, _eval.Evaluate(i).State));
    }
}
