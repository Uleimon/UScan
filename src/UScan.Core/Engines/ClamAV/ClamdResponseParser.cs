using System.Globalization;
using System.Text.RegularExpressions;
using UScan.Core.Model;

namespace UScan.Core.Engines.ClamAV;

/// <summary>
/// Parses clamd replies. Kept separate from the socket code so every reply shape
/// can be unit-tested without a running daemon.
/// Reference: clamd(8), section "COMMANDS" (INSTREAM, VERSION, PING).
/// </summary>
internal static partial class ClamdResponseParser
{
    public const string EngineId = "clamav";

    // ClamAV reports these when it could NOT inspect everything (only with AlertExceedsMax /
    // AlertEncrypted enabled). They describe a scan limitation, not malware.
    private static readonly string[] IncompletePrefixes =
    [
        "Heuristics.Limits.Exceeded",
        "Heuristics.Encrypted",
    ];

    public static EngineResult ParseScanReply(string reply)
    {
        var text = reply.TrimEnd('\0', '\n', '\r', ' ');

        if (text.EndsWith(" ERROR", StringComparison.Ordinal))
        {
            return new EngineResult(Verdict.Error, EngineId, null, text);
        }

        // Normal replies are "<id>: OK" or "<id>: <name> FOUND" where <id> is "stream" for INSTREAM.
        var colon = text.IndexOf(": ", StringComparison.Ordinal);
        if (colon < 0)
        {
            return new EngineResult(Verdict.Error, EngineId, null, $"Unrecognised clamd reply: '{text}'");
        }

        var body = text[(colon + 2)..];
        if (body == "OK")
        {
            return new EngineResult(Verdict.Clean, EngineId, null, text);
        }

        if (body.EndsWith(" FOUND", StringComparison.Ordinal))
        {
            var name = body[..^" FOUND".Length].Trim();
            if (name.Length == 0)
            {
                return new EngineResult(Verdict.Error, EngineId, null, $"Detection without name: '{text}'");
            }

            if (IncompletePrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
            {
                return new EngineResult(Verdict.Incomplete, EngineId, name, text);
            }

            // Any other Heuristics.* (e.g. Heuristics.Broken.Executable, Heuristics.Phishing) is a
            // heuristic, not a signature match: report as suspicious so it is reviewed, not removed.
            var verdict = name.StartsWith("Heuristics.", StringComparison.Ordinal) ? Verdict.Suspicious : Verdict.Infected;
            return new EngineResult(verdict, EngineId, name, text);
        }

        return new EngineResult(Verdict.Error, EngineId, null, $"Unrecognised clamd reply: '{text}'");
    }

    /// <summary>Parses "ClamAV 1.5.4/27800/Tue Oct 27 08:23:45 2026". Database parts are absent when clamd has none loaded.</summary>
    public static EngineInfo ParseVersion(string reply)
    {
        var text = reply.TrimEnd('\0', '\n', '\r', ' ');
        var m = VersionRegex().Match(text);
        if (!m.Success)
        {
            throw new EngineUnavailableException($"Unrecognised clamd VERSION reply: '{text}'");
        }

        long? dbVersion = m.Groups["db"].Success ? long.Parse(m.Groups["db"].Value, CultureInfo.InvariantCulture) : null;
        DateTimeOffset? dbTime = null;
        if (m.Groups["date"].Success)
        {
            var normalized = WhitespaceRegex().Replace(m.Groups["date"].Value.Trim(), " ");
            if (DateTime.TryParseExact(normalized, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var parsed))
            {
                dbTime = new DateTimeOffset(parsed);
            }
        }

        return new EngineInfo(EngineId, m.Groups["ver"].Value, dbVersion, dbTime);
    }

    [GeneratedRegex(@"^ClamAV (?<ver>[0-9][0-9A-Za-z.\-]*)(?:/(?<db>[0-9]+)(?:/(?<date>.+))?)?$")]
    private static partial Regex VersionRegex();

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();
}
