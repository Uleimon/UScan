using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;
using UScan.Core.Updates;

namespace UScan.Core.Tests.Unit;

public sealed class UpdateVerifierTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);
    private readonly ECDsa _releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _publicOnly;

    public UpdateVerifierTests()
    {
        _publicOnly = UpdateVerifier.LoadPublicKey(_releaseKey.ExportSubjectPublicKeyInfoPem());
    }

    public void Dispose()
    {
        _releaseKey.Dispose();
        _otherKey.Dispose();
        _publicOnly.Dispose();
    }

    private UpdateVerifier Verifier(string installed = "1.0.0") =>
        new(new Dictionary<string, ECDsa> { ["release-2026"] = _publicOnly }, Version.Parse(installed), "stable", new FakeTimeProvider(Now));

    private static byte[] Manifest(string version = "1.1.0", DateTimeOffset? expires = null, string product = "UScan", string keyId = "release-2026", string sha = "") =>
        JsonSerializer.SerializeToUtf8Bytes(new UpdateManifest(product, "stable", version, Now.AddHours(-1), expires ?? Now.AddDays(7), keyId,
            new UpdatePackage("uscan.zip", sha.Length == 64 ? sha : new string('a', 64), 100)), UpdateVerifier.Json);

    private byte[] Sign(byte[] data, ECDsa? key = null) => (key ?? _releaseKey).SignData(data, HashAlgorithmName.SHA256);

    [Fact]
    public void Valid_manifest_is_accepted()
    {
        var m = Manifest();
        var r = Verifier().Verify(m, Sign(m));
        Assert.True(r.Accepted, r.Reason);
        Assert.Equal("1.1.0", r.Manifest!.Version);
    }

    [Fact]
    public void Der_encoded_signature_is_accepted()
    {
        var m = Manifest();
        var der = _releaseKey.SignData(m, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(Verifier().Verify(m, der).Accepted);
    }

    [Fact]
    public void Modified_manifest_is_rejected()
    {
        var m = Manifest();
        var sig = Sign(m);
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(m).Replace("1.1.0", "9.9.9", StringComparison.Ordinal));
        Assert.Contains("Signature", Verifier().Verify(tampered, sig).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Signature_from_untrusted_key_is_rejected()
    {
        var m = Manifest();
        Assert.False(Verifier().Verify(m, Sign(m, _otherKey)).Accepted);
    }

    [Fact]
    public void Unknown_key_id_is_rejected()
    {
        var m = Manifest(keyId: "attacker");
        Assert.Contains("unknown key", Verifier().Verify(m, Sign(m)).Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("1.0.0")]
    [InlineData("0.9.0")]
    public void Downgrade_and_replay_are_rejected(string offered)
    {
        var m = Manifest(offered);
        Assert.Contains("downgrade", Verifier("1.0.0").Verify(m, Sign(m)).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Expired_manifest_is_rejected()
    {
        var m = Manifest(expires: Now.AddMinutes(-1));
        Assert.Contains("expired", Verifier().Verify(m, Sign(m)).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Wrong_product_is_rejected_even_if_signed()
    {
        var m = Manifest(product: "OtherApp");
        Assert.False(Verifier().Verify(m, Sign(m)).Accepted);
    }

    [Fact]
    public void Garbage_is_rejected_without_exception()
    {
        Assert.False(Verifier().Verify("not json"u8, new byte[64]).Accepted);
        Assert.False(Verifier().Verify("{\"product\":\"UScan\",\"extra\":1}"u8, new byte[64]).Accepted);
    }

    [Fact]
    public void Non_p256_keys_are_refused()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<CryptographicException>(() => UpdateVerifier.LoadPublicKey(p384.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public void Package_hash_and_size_are_enforced()
    {
        var data = Encoding.UTF8.GetBytes("package content");
        var good = new UpdatePackage("p.zip", Convert.ToHexStringLower(SHA256.HashData(data)), data.Length);
        Assert.True(UpdateVerifier.VerifyPackage(new MemoryStream(data), good, out _));
        Assert.False(UpdateVerifier.VerifyPackage(new MemoryStream(data), good with { Sha256 = new string('0', 64) }, out _));
        Assert.False(UpdateVerifier.VerifyPackage(new MemoryStream(data), good with { Size = data.Length - 1 }, out var r1));
        Assert.Contains("larger", r1, StringComparison.Ordinal);
        Assert.False(UpdateVerifier.VerifyPackage(new MemoryStream(data), good with { Size = data.Length + 1 }, out _));
    }
}

public class StagedInstallerTests
{
    private static MemoryStream Zip(params (string Name, string Content)[] entries) =>
        new(TestFiles.Zip(entries.Select(e => (e.Name, Encoding.UTF8.GetBytes(e.Content))).ToArray()));

    [Fact]
    public void Install_switches_only_after_self_test_and_can_roll_back()
    {
        using var dir = new TempDir();
        var inst = new StagedInstaller(dir.Path);

        Assert.True(inst.Install(Zip(("uscan.exe", "v1")), new Version(1, 0), _ => true).Success);
        Assert.Equal("1.0", inst.ActiveVersion);

        var failed = inst.Install(Zip(("uscan.exe", "broken")), new Version(1, 1), _ => false);
        Assert.False(failed.Success);
        Assert.Equal("1.0", inst.ActiveVersion);
        Assert.Single(Directory.GetDirectories(Path.Combine(dir.Path, "versions")));

        Assert.True(inst.Install(Zip(("uscan.exe", "v2")), new Version(2, 0), d => File.ReadAllText(Path.Combine(d, "uscan.exe")) == "v2").Success);
        Assert.Equal("2.0", inst.ActiveVersion);

        Assert.True(inst.Rollback().Success);
        Assert.Equal("1.0", inst.ActiveVersion);
        Assert.Equal("v1", File.ReadAllText(Path.Combine(inst.ActiveDirectory!, "uscan.exe")));
    }

    [Theory]
    [InlineData("../evil.txt")]
    [InlineData("sub/../../evil.txt")]
    public void Path_traversal_entries_are_rejected(string entry)
    {
        using var dir = new TempDir();
        var inst = new StagedInstaller(Path.Combine(dir.Path, "app"));
        var r = inst.Install(Zip(("ok.txt", "x"), (entry, "pwned")), new Version(1, 0), _ => true);

        Assert.False(r.Success);
        Assert.Contains("outside", r.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(dir.Path, "evil.txt")));
        Assert.False(File.Exists(Path.Combine(dir.Path, "app", "evil.txt")));
        Assert.Null(inst.ActiveVersion);
        Assert.Empty(Directory.GetDirectories(Path.Combine(dir.Path, "app", "versions")));
    }

    [Fact]
    public void Decompression_bomb_is_rejected()
    {
        using var dir = new TempDir();
        var inst = new StagedInstaller(dir.Path, maxExtractedBytes: 1024 * 1024);
        var r = inst.Install(new MemoryStream(TestFiles.ZipWithZeros(5 * 1024 * 1024)), new Version(1, 0), _ => true);
        Assert.False(r.Success);
        Assert.Contains("allowed size", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Corrupt_package_fails_cleanly()
    {
        using var dir = new TempDir();
        var r = new StagedInstaller(dir.Path).Install(new MemoryStream("PK\u0003\u0004junk"u8.ToArray()), new Version(1, 0), _ => true);
        Assert.False(r.Success);
    }
}

public class FreshclamUpdaterTests
{
    private sealed class FakeRunner(ProcessResult result) : IProcessRunner
    {
        public IReadOnlyList<string>? Args;

        public Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
        {
            Args = arguments;
            return Task.FromResult(result);
        }
    }

    private static string FakeExe(TempDir dir) => dir.Write("freshclam", "");

    [Fact]
    public async Task Success_and_up_to_date_are_distinguished()
    {
        using var dir = new TempDir();
        var updated = await new FreshclamUpdater(FakeExe(dir), null, new FakeRunner(new(0, "daily.cvd updated (version: 27800, sigs: 2000)", false))).UpdateAsync(TestContext.Current.CancellationToken);
        Assert.True(updated.Success);
        Assert.False(updated.UpToDate);

        var current = await new FreshclamUpdater(FakeExe(dir), null, new FakeRunner(new(0, "daily.cld database is up-to-date (version: 27800)", false))).UpdateAsync(TestContext.Current.CancellationToken);
        Assert.True(current.Success);
        Assert.True(current.UpToDate);
    }

    [Theory]
    [InlineData(52, "network")]
    [InlineData(54, "signature verification")]
    [InlineData(99, "unexpected")]
    public async Task Failures_are_explained_and_logged(int code, string expected)
    {
        using var dir = new TempDir();
        var log = new JsonLinesEventLog(Path.Combine(dir.Path, "log"));
        var r = await new FreshclamUpdater(FakeExe(dir), null, new FakeRunner(new(code, "ERROR: something", false)), log).UpdateAsync(TestContext.Current.CancellationToken);
        Assert.False(r.Success);
        Assert.Contains(expected, r.Summary, StringComparison.Ordinal);
        Assert.Contains(log.ReadRecent(), e => e.Category == "update" && e.Severity == EventSeverity.Error);
    }

    [Fact]
    public async Task Timeout_and_missing_executable_fail()
    {
        using var dir = new TempDir();
        Assert.False((await new FreshclamUpdater(FakeExe(dir), null, new FakeRunner(new(-1, "", true))).UpdateAsync(TestContext.Current.CancellationToken)).Success);
        Assert.False((await new FreshclamUpdater(Path.Combine(dir.Path, "missing"), null).UpdateAsync(TestContext.Current.CancellationToken)).Success);
    }

    [Fact]
    public async Task Config_file_is_passed_as_single_argument()
    {
        using var dir = new TempDir();
        var runner = new FakeRunner(new(0, "", false));
        await new FreshclamUpdater(FakeExe(dir), "C:\\Program Files\\ClamAV\\freshclam.conf", runner).UpdateAsync(TestContext.Current.CancellationToken);
        Assert.Contains("--config-file=C:\\Program Files\\ClamAV\\freshclam.conf", runner.Args!);
    }
}
