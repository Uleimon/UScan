using UScan.Core.Model;
using UScan.Core.Status;

namespace UScan.Desktop.ViewModels;

internal static class Texts
{
    public static string State(ProtectionState s) => s switch
    {
        ProtectionState.Protected => "Geschützt",
        ProtectionState.ScanRunning => "Scan läuft",
        ProtectionState.UpdateRequired => "Update erforderlich",
        ProtectionState.ProtectionLimited => "Schutz eingeschränkt",
        ProtectionState.ActionRequired => "Aktion erforderlich",
        ProtectionState.ThreatFound => "Bedrohung gefunden",
        _ => "Status unbekannt",
    };

    /// <summary>Resource key of the banner brush. Only "Protected" is green.</summary>
    public static string StateBrushKey(ProtectionState s) => s switch
    {
        ProtectionState.Protected => "OkBrush",
        ProtectionState.ScanRunning => "InfoBrush",
        ProtectionState.UpdateRequired or ProtectionState.ProtectionLimited => "WarnBrush",
        ProtectionState.ActionRequired => "ActionBrush",
        ProtectionState.ThreatFound => "DangerBrush",
        _ => "NeutralBrush",
    };

    public static string Verdict(Verdict v) => v switch
    {
        Core.Model.Verdict.Clean => "Ohne Befund",
        Core.Model.Verdict.Infected => "Infiziert",
        Core.Model.Verdict.Suspicious => "Verdächtig",
        Core.Model.Verdict.Incomplete => "Unvollständig geprüft",
        Core.Model.Verdict.Skipped => "Übersprungen",
        _ => "Fehler",
    };
}
