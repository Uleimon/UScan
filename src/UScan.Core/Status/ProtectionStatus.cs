using UScan.Core.Model;

namespace UScan.Core.Status;

/// <summary>Overall state shown on the dashboard. Order matters: higher values win.</summary>
public enum ProtectionState
{
    Protected = 0,
    ScanRunning = 1,
    UpdateRequired = 2,
    ProtectionLimited = 3,
    ActionRequired = 4,
    ThreatFound = 5,
    Unknown = 6,
}

public sealed record StatusInputs(
    bool EngineReachable,
    EngineInfo? Engine,
    bool ScanRunning,
    int UnresolvedThreats,
    int PendingActions,
    bool? OnAccessProtectionActive,
    bool? FileMonitorActive);

public sealed record StatusAssessment(ProtectionState State, IReadOnlyList<string> Reasons);

/// <summary>
/// Derives the dashboard state from facts. "Protected" is only returned when every
/// required fact is positively known to be good; missing information is never treated as good.
/// </summary>
public sealed class StatusEvaluator
{
    public StatusEvaluator(TimeSpan maxSignatureAge, TimeProvider? time = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxSignatureAge, TimeSpan.Zero);
        MaxSignatureAge = maxSignatureAge;
        _time = time ?? TimeProvider.System;
    }

    private readonly TimeProvider _time;

    public TimeSpan MaxSignatureAge { get; }

    public StatusAssessment Evaluate(StatusInputs? inputs)
    {
        if (inputs is null)
        {
            return new StatusAssessment(ProtectionState.Unknown, ["No status information available."]);
        }

        var reasons = new List<string>();
        var state = ProtectionState.Protected;

        void Raise(ProtectionState s, string reason)
        {
            reasons.Add(reason);
            if (s > state)
            {
                state = s;
            }
        }

        if (inputs.UnresolvedThreats > 0)
        {
            Raise(ProtectionState.ThreatFound, $"{inputs.UnresolvedThreats} detection(s) not yet resolved.");
        }

        if (inputs.PendingActions > 0)
        {
            Raise(ProtectionState.ActionRequired, $"{inputs.PendingActions} action(s) waiting for confirmation.");
        }

        if (!inputs.EngineReachable)
        {
            Raise(ProtectionState.ProtectionLimited, "Scan engine is not reachable.");
        }
        else if (inputs.Engine is null)
        {
            Raise(ProtectionState.ProtectionLimited, "Engine version could not be determined.");
        }
        else if (inputs.Engine.DatabaseTimestamp is not { } dbTime)
        {
            Raise(ProtectionState.UpdateRequired, "Signature database age is unknown or no database is loaded.");
        }
        else
        {
            var age = _time.GetUtcNow() - dbTime;
            if (age > MaxSignatureAge)
            {
                Raise(ProtectionState.UpdateRequired, $"Signatures are {age.TotalDays:F0} days old (limit {MaxSignatureAge.TotalDays:F0}).");
            }
        }

        // On-access (blocking) protection comes from Microsoft Defender or another registered
        // antivirus; UScan has no driver of its own and therefore cannot provide it.
        if (inputs.OnAccessProtectionActive is null)
        {
            Raise(ProtectionState.ProtectionLimited, "State of on-access protection (Microsoft Defender real-time protection) is unknown.");
        }
        else if (inputs.OnAccessProtectionActive == false)
        {
            Raise(ProtectionState.ProtectionLimited, "On-access protection (Microsoft Defender real-time protection) is off. UScan cannot block files itself.");
        }

        if (inputs.FileMonitorActive is null)
        {
            Raise(ProtectionState.ProtectionLimited, "State of UScan file monitoring is unknown.");
        }
        else if (inputs.FileMonitorActive == false)
        {
            Raise(ProtectionState.ProtectionLimited, "UScan file monitoring (re-scan after change) is not running.");
        }

        if (inputs.ScanRunning && state == ProtectionState.Protected)
        {
            state = ProtectionState.ScanRunning;
            reasons.Add("A scan is in progress.");
        }

        return new StatusAssessment(state, reasons);
    }
}
