using UScan.Core.Model;
using UScan.Core.Status;
using UScan.Core.Storage;

namespace UScan.Desktop.ViewModels;

/// <summary>Colour category of a finding, in the order it is listed (most serious first).</summary>
internal enum FindingCategory
{
    /// <summary>Red: a signature engine (ClamAV, Defender) recognised malware. Remove it.</summary>
    Serious,

    /// <summary>Yellow: only a heuristic (UScan's or ClamAV's Heuristics.*) found it unusual. Check it; often harmless.</summary>
    Minor,

    /// <summary>Not checked completely (error, skipped, incomplete). Shown grey; not "okay".</summary>
    Unchecked,

    /// <summary>Blue: the user allowed this exact file content as a false positive.</summary>
    FalseAlarm,

    /// <summary>Green: nothing found.</summary>
    Ok,
}

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

    public static FindingCategory Category(Verdict v, bool allowedByUser) => v switch
    {
        _ when allowedByUser && v is Core.Model.Verdict.Infected or Core.Model.Verdict.Suspicious => FindingCategory.FalseAlarm,
        Core.Model.Verdict.Infected => FindingCategory.Serious,
        Core.Model.Verdict.Suspicious => FindingCategory.Minor,
        Core.Model.Verdict.Clean => FindingCategory.Ok,
        _ => FindingCategory.Unchecked,
    };

    /// <summary>Category of a log line: threats red, heuristic hits and other warnings yellow, false positives blue, the rest green.</summary>
    public static FindingCategory Category(SecurityEvent e) => e switch
    {
        { Category: "allowlist" } => FindingCategory.FalseAlarm,
        _ when e.Message.Contains("allowed by user", StringComparison.Ordinal) => FindingCategory.FalseAlarm,
        { Severity: EventSeverity.Threat } => FindingCategory.Serious,
        { Severity: EventSeverity.Warning or EventSeverity.Error } => FindingCategory.Minor,
        _ => FindingCategory.Ok,
    };

    public static string CategoryLabel(FindingCategory c) => c switch
    {
        FindingCategory.Serious => "ERNST – entfernen",
        FindingCategory.Minor => "Nicht so schlimm – prüfen",
        FindingCategory.FalseAlarm => "Fehlalarm",
        FindingCategory.Ok => "Okay",
        _ => "Nicht geprüft",
    };

    /// <summary>Short label for log lines, where yellow also covers ordinary warnings.</summary>
    public static string LogLabel(FindingCategory c) => c switch
    {
        FindingCategory.Serious => "ERNST",
        FindingCategory.Minor => "Achtung",
        FindingCategory.FalseAlarm => "Fehlalarm",
        _ => "Okay",
    };

    public static string CategoryBrushKey(FindingCategory c) => c switch
    {
        FindingCategory.Serious => "DangerBrush",
        FindingCategory.Minor => "MinorBrush",
        FindingCategory.FalseAlarm => "InfoBrush",
        FindingCategory.Ok => "OkBrush",
        _ => "NeutralBrush",
    };

    /// <summary>Text on the coloured label: dark on yellow (readable), white otherwise.</summary>
    public static string CategoryTextBrushKey(FindingCategory c) => c == FindingCategory.Minor ? "OnMinorBrush" : "OnAccentBrush";

    public static string Mode(Core.Scanning.ScanMode m) => m switch
    {
        Core.Scanning.ScanMode.Quick => "Schnellscan",
        Core.Scanning.ScanMode.Full => "vollständiger Scan",
        Core.Scanning.ScanMode.Autostart => "Autostart-Scan",
        _ => "Ordner-Scan",
    };
}
