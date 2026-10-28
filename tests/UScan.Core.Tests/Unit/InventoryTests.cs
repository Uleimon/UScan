using UScan.Core.Inventory;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class CommandLineResolverTests
{
    private static CommandLineResolver Resolver(params string[] existing) =>
        new(p => existing.Contains(p, StringComparer.OrdinalIgnoreCase), [@"C:\Windows\System32"], s => s.Replace("%SystemRoot%", @"C:\Windows", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void Quoted_path_with_arguments()
    {
        var r = Resolver().Resolve("\"C:\\Program Files\\App\\app.exe\" --tray");
        Assert.Equal(@"C:\Program Files\App\app.exe", r.Executable);
        Assert.Null(r.Target);
        Assert.Empty(r.Observations);
    }

    [Fact]
    public void Unquoted_path_with_spaces_is_resolved_and_flagged()
    {
        var r = Resolver(@"C:\Program Files\My App\app.exe").Resolve(@"C:\Program Files\My App\app.exe -bg");
        Assert.Equal(@"C:\Program Files\My App\app.exe", r.Executable);
        Assert.Contains(r.Observations, o => o.Contains("Unquoted path", StringComparison.Ordinal));
    }

    [Fact]
    public void Environment_variables_and_nt_prefixes_are_expanded()
    {
        Assert.Equal(@"C:\Windows\system32\svchost.exe", Resolver(@"C:\Windows\system32\svchost.exe").Resolve(@"%SystemRoot%\system32\svchost.exe -k netsvcs").Executable);
        Assert.Equal(@"C:\Windows\system32\drivers\x.sys", Resolver().Resolve(@"\SystemRoot\system32\drivers\x.sys").Executable);
        Assert.Equal(@"C:\drv\y.sys", Resolver().Resolve(@"\??\C:\drv\y.sys").Executable);
    }

    [Fact]
    public void Bare_name_is_searched_in_system_directories()
    {
        var r = Resolver(@"C:\Windows\System32\rundll32.exe").Resolve(@"rundll32.exe C:\Users\a\AppData\Roaming\x.dll,Start");
        Assert.Equal(@"C:\Windows\System32\rundll32.exe", r.Executable);
        Assert.Equal(@"C:\Users\a\AppData\Roaming\x.dll", r.Target);
        Assert.Contains(r.Observations, o => o.Contains("rundll32", StringComparison.Ordinal));
    }

    [Fact]
    public void Script_host_target_and_risky_arguments_are_reported()
    {
        var r = Resolver().Resolve(@"powershell.exe -NoProfile -WindowStyle Hidden -File ""C:\Users\a\AppData\Local\Temp\run.ps1""");
        Assert.Equal(@"C:\Users\a\AppData\Local\Temp\run.ps1", r.Target);

        var enc = Resolver().Resolve("powershell.exe -enc SQBFAFgA");
        Assert.Contains(enc.Observations, o => o.Contains("encoded", StringComparison.Ordinal));

        var url = Resolver().Resolve("mshta.exe https://example.invalid/a.hta");
        Assert.Contains(url.Observations, o => o.Contains("URL", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\"C:\\unterminated")]
    public void Malformed_input_does_not_throw(string? cmd)
    {
        var r = Resolver().Resolve(cmd);
        Assert.Null(r.Executable);
        Assert.NotEmpty(r.Observations);
    }

    [Fact]
    public void Tokenizer_handles_quotes()
    {
        Assert.Equal(["a", "b c", "d"], CommandLineResolver.Tokenize("a \"b c\"  d"));
    }
}

public class InventoryEntryFactoryTests
{
    private sealed class FixedVerifier(SignatureStatus status) : ISignatureVerifier
    {
        public SignatureInfo Verify(string path) => new(status, null, null);
    }

    [Fact]
    public void Existing_file_gets_hash_signature_and_observations()
    {
        using var dir = new TempDir();
        var file = dir.Write("AppData/Roaming/evil.exe", TestFiles.Eicar);
        var f = new InventoryEntryFactory(new CommandLineResolver(), new FixedVerifier(SignatureStatus.NotSigned));

        // Use the OS separator so the user-writable check works on every platform.
        var e = f.Create(InventoryKind.RegistryRun, "HKCU\\Run", "x", $"\"{file}\" /s");

        Assert.True(e.FileExists);
        Assert.Equal(TestFiles.EicarSha256, e.Sha256);
        Assert.Equal(SignatureStatus.NotSigned, e.Signature!.Status);
        Assert.Contains(e.Observations, o => o.Contains("not digitally signed", StringComparison.Ordinal));
        Assert.Contains(e.Observations, o => o.Contains("user-writable", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_file_is_reported_without_hash()
    {
        var f = new InventoryEntryFactory(new CommandLineResolver(), new FixedVerifier(SignatureStatus.Valid));
        var missing = Path.Combine(Path.GetTempPath(), "uscan-does-not-exist", "a.exe");
        var e = f.Create(InventoryKind.Service, "loc", "svc", $"\"{missing}\"");
        Assert.False(e.FileExists);
        Assert.Null(e.Sha256);
        Assert.Contains(e.Observations, o => o.Contains("does not exist", StringComparison.Ordinal));
    }

    [Fact]
    public void Invalid_signature_is_reported()
    {
        using var dir = new TempDir();
        var file = dir.Write("a.exe", "x");
        var e = new InventoryEntryFactory(new CommandLineResolver(), new FixedVerifier(SignatureStatus.Invalid)).Create(InventoryKind.RegistryRun, "l", "n", $"\"{file}\"");
        Assert.Contains(e.Observations, o => o.Contains("INVALID", StringComparison.Ordinal));
    }

    [Fact]
    public void Diff_detects_added_modified_removed()
    {
        static InventoryEntry E(string name, string cmd) => new(InventoryKind.RegistryRun, "HKCU\\Run", name, cmd, null, null, null, null, []);
        var before = new InventorySnapshot(DateTimeOffset.UnixEpoch, [E("keep", "a"), E("change", "b"), E("gone", "c")], []);
        var after = new InventorySnapshot(DateTimeOffset.UnixEpoch, [E("keep", "a"), E("change", "B2"), E("new", "d")], []);

        var d = InventoryDiff.Compare(before, after);
        Assert.Equal(3, d.Count);
        Assert.Contains(d, c => c.ChangeType == "Added" && c.Entry.Name == "new");
        Assert.Contains(d, c => c.ChangeType == "Modified" && c.Entry.Name == "change" && c.Previous!.Command == "b");
        Assert.Contains(d, c => c.ChangeType == "Removed" && c.Entry.Name == "gone");
    }

    [Fact]
    public void Failing_source_is_reported_not_fatal()
    {
        var snap = new InventoryCollector([new ThrowingSource(), new OkSource()]).Collect();
        Assert.Single(snap.Entries);
        Assert.Contains(snap.Errors, e => e.Contains("boom", StringComparison.Ordinal));
    }

    private sealed class ThrowingSource : IInventorySource
    {
        public string Name => "throwing";
        public IEnumerable<InventoryEntry> Collect(ICollection<string> errors) => throw new UnauthorizedAccessException("boom");
    }

    private sealed class OkSource : IInventorySource
    {
        public string Name => "ok";
        public IEnumerable<InventoryEntry> Collect(ICollection<string> errors) => [new InventoryEntry(InventoryKind.Service, "l", "n", null, null, null, null, null, [])];
    }
}
