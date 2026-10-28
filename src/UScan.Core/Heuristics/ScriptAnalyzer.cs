using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace UScan.Core.Heuristics;

/// <summary>
/// Pattern-based analysis of scripts (PowerShell, VBScript/JScript, batch, HTA) and a macro
/// presence check for Office Open XML documents. Each rule has a weight and an explanation;
/// one rule alone never reaches the threshold.
/// </summary>
public sealed partial class ScriptAnalyzer : IHeuristicAnalyzer
{
    public const int MaxBytes = 2 * 1024 * 1024;

    private static readonly string[] ScriptExtensions = [".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"];
    private static readonly string[] MacroDocuments = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".docx", ".xlsx", ".pptx"];

    private sealed record Rule(string Id, int Weight, Regex Pattern, string Reason);

    private static readonly Rule[] Rules =
    [
        new("ps.encoded", 25, EncodedCommand(), "Runs a Base64-encoded PowerShell command."),
        new("ps.iex", 15, Iex(), "Executes dynamically built code (Invoke-Expression/IEX)."),
        new("net.download", 15, Download(), "Downloads content from the internet."),
        new("ps.b64", 10, FromBase64(), "Decodes Base64 data at runtime."),
        new("ps.hidden", 10, Hidden(), "Starts a hidden window."),
        new("ps.reflect", 20, ReflectLoad(), "Loads a .NET assembly from memory."),
        new("av.tamper", 40, DefenderTamper(), "Tries to disable or add exclusions to Microsoft Defender."),
        new("ransom.shadows", 40, ShadowDelete(), "Deletes shadow copies or backup catalogs (typical ransomware preparation)."),
        new("ransom.recovery", 25, RecoveryOff(), "Disables Windows recovery options."),
        new("lolbin.certutil", 25, Certutil(), "Uses certutil to download or decode files."),
        new("lolbin.bits", 20, Bitsadmin(), "Uses bitsadmin to transfer files."),
        new("persist.run", 15, RunKey(), "Writes an autostart Run key."),
        new("persist.task", 10, Schtasks(), "Creates a scheduled task."),
        new("vbs.shellrun", 10, ShellRun(), "Starts programs through WScript.Shell."),
        new("vbs.http", 15, XmlHttp(), "Performs HTTP requests via MSXML/WinHttp."),
        new("vbs.stream", 15, AdoStream(), "Writes binary data to disk via ADODB.Stream."),
        new("js.obfuscation", 15, JsObfuscation(), "Uses eval together with character-code or unescape decoding (obfuscation)."),
    ];

    public bool CanAnalyze(string path, ReadOnlySpan<byte> header)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ScriptExtensions.Contains(ext) || (MacroDocuments.Contains(ext) && header.StartsWith("PK\u0003\u0004"u8));
    }

    public HeuristicResult Analyze(string path, Stream content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var ext = Path.GetExtension(path).ToLowerInvariant();
        var features = new List<HeuristicFeature>();

        if (MacroDocuments.Contains(ext))
        {
            AnalyzeOfficeDocument(content, ext, features);
            return HeuristicScorer.Score(features);
        }

        var text = ReadText(content);
        if (text is null)
        {
            return HeuristicResult.None;
        }

        foreach (var r in Rules)
        {
            if (SafeMatch(r.Pattern, text))
            {
                features.Add(new HeuristicFeature(r.Id, r.Weight, r.Reason));
            }
        }

        // Combinations that describe one complete malicious technique, not just capabilities.
        var ids = features.Select(f => f.Id).ToHashSet();
        if (ids.Contains("net.download") && ids.Contains("ps.iex"))
        {
            features.Add(new("combo.cradle", 35, "Downloads code and executes it directly in memory (download cradle)."));
        }

        if (ids.Contains("vbs.http") && ids.Contains("vbs.stream") && ids.Contains("vbs.shellrun"))
        {
            features.Add(new("combo.dropper", 35, "Downloads a file, writes it to disk and starts it (dropper chain)."));
        }

        if (SafeMatch(LongBase64(), text))
        {
            features.Add(new("obf.blob", 10, "Contains a long Base64-like data block."));
        }

        return HeuristicScorer.Score(features);
    }

    private static void AnalyzeOfficeDocument(Stream content, string ext, List<HeuristicFeature> features)
    {
        try
        {
            using var ms = new MemoryStream();
            content.CopyTo(ms);
            ms.Position = 0;
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            var vba = zip.Entries.Any(e => e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
            if (vba)
            {
                features.Add(new("office.macro", 15, "Document contains VBA macros."));
                if (!ext.EndsWith('m'))
                {
                    features.Add(new("office.macro.mismatch", 30, $"Macros inside a '{ext}' file, which normally cannot contain macros (renamed to hide them)."));
                }
            }

            if (zip.Entries.Any(e => e.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase) && ContainsExternalTemplate(e)))
            {
                features.Add(new("office.remote", 25, "Document loads an external template or object from a URL."));
            }
        }
        catch (InvalidDataException)
        {
            // Damaged documents are not judged by this analyzer.
        }
    }

    private static bool ContainsExternalTemplate(ZipArchiveEntry e)
    {
        if (e.Length > 1024 * 1024)
        {
            return false;
        }

        using var r = new StreamReader(e.Open());
        var xml = r.ReadToEnd();
        return xml.Contains("TargetMode=\"External\"", StringComparison.Ordinal)
               && (xml.Contains("attachedTemplate", StringComparison.Ordinal) || xml.Contains("oleObject", StringComparison.Ordinal))
               && xml.Contains("http", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Regexes run with a timeout; a pathological input skips the rule instead of hanging the scan.</summary>
    private static bool SafeMatch(Regex r, string text)
    {
        try
        {
            return r.IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static string? ReadText(Stream s)
    {
        var buffer = new byte[MaxBytes];
        var n = s.ReadAtLeast(buffer, MaxBytes, throwOnEndOfStream: false);
        if (n == MaxBytes && s.ReadByte() != -1)
        {
            return null; // too large: not analysed
        }

        var span = buffer.AsSpan(0, n);
        // UTF-16 LE scripts (common for PowerShell) have a BOM or many zero bytes.
        if (span.StartsWith(new byte[] { 0xFF, 0xFE }) || (n > 16 && span.Count((byte)0) > n / 3))
        {
            return Encoding.Unicode.GetString(span);
        }

        return Encoding.UTF8.GetString(span);
    }

    [GeneratedRegex(@"-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", RegexOptions.IgnoreCase, 500)]
    private static partial Regex EncodedCommand();

    [GeneratedRegex(@"\b(Invoke-Expression|IEX)\b\s*[\(\$""']", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Iex();

    [GeneratedRegex(@"(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Start-BitsTransfer|Net\.WebClient|URLDownloadToFile)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Download();

    [GeneratedRegex(@"FromBase64String", RegexOptions.IgnoreCase, 500)]
    private static partial Regex FromBase64();

    [GeneratedRegex(@"(-w(indowstyle)?\s+h(idden)?\b|WindowStyle\s*=?\s*['""]?Hidden)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Hidden();

    [GeneratedRegex(@"(Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]::Load)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex ReflectLoad();

    [GeneratedRegex(@"(Set-MpPreference\s+.*-Disable\w+\s+\$?true|Add-MpPreference\s+.*-Exclusion(Path|Process|Extension)|DisableAntiSpyware|DisableRealtimeMonitoring\s+\$?(true|1))", RegexOptions.IgnoreCase, 500)]
    private static partial Regex DefenderTamper();

    [GeneratedRegex(@"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|Win32_ShadowCopy.*Delete)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex ShadowDelete();

    [GeneratedRegex(@"bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex RecoveryOff();

    [GeneratedRegex(@"certutil(\.exe)?\s+.*(-urlcache|-decode|-decodehex)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Certutil();

    [GeneratedRegex(@"bitsadmin(\.exe)?\s+.*/transfer", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Bitsadmin();

    [GeneratedRegex(@"(reg(\.exe)?\s+add\s+.*\\CurrentVersion\\Run|New-ItemProperty\s+.*\\CurrentVersion\\Run|RegWrite\s*\(?\s*""HK(CU|LM|EY_CURRENT_USER|EY_LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex RunKey();

    [GeneratedRegex(@"(schtasks(\.exe)?\s+/create|Register-ScheduledTask)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex Schtasks();

    [GeneratedRegex(@"WScript\.Shell[""']?\s*\)[\s\S]{0,400}\.Run\b|\.ShellExecute\b", RegexOptions.IgnoreCase, 500)]
    private static partial Regex ShellRun();

    [GeneratedRegex(@"(MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP)", RegexOptions.IgnoreCase, 500)]
    private static partial Regex XmlHttp();

    [GeneratedRegex(@"ADODB\.Stream[\s\S]{0,600}SaveToFile", RegexOptions.IgnoreCase, 500)]
    private static partial Regex AdoStream();

    [GeneratedRegex(@"\beval\s*\([\s\S]{0,200}(String\.fromCharCode|unescape\s*\(|atob\s*\()", RegexOptions.IgnoreCase, 500)]
    private static partial Regex JsObfuscation();

    [GeneratedRegex(@"[A-Za-z0-9+/]{400,}={0,2}", RegexOptions.None, 500)]
    private static partial Regex LongBase64();
}
