using System.Security.Cryptography;
using UScan.Core.Model;
using UScan.Core.Quarantine;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public sealed class QuarantineTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TempDir _work = new();
    private readonly TempDir _store = new();
    private readonly QuarantineStore _q;
    private readonly JsonLinesEventLog _log;

    public QuarantineTests()
    {
        _log = new JsonLinesEventLog(Path.Combine(_store.Path, "logs"));
        _q = new QuarantineStore(Path.Combine(_store.Path, "q"), new ProtectedLocationsPolicy([Path.Combine(_work.Path, "system")]), _log);
    }

    public void Dispose()
    {
        _work.Dispose();
        _store.Dispose();
    }

    private static string Sha(byte[] d) => Convert.ToHexStringLower(SHA256.HashData(d));

    [Fact]
    public async Task Quarantine_removes_original_and_stores_verifiable_encrypted_copy()
    {
        var path = _work.Write("dl/eicar.com", TestFiles.Eicar);

        var r = await _q.QuarantineAsync(path, "Test.EICAR", "clamav", TestFiles.EicarSha256, ct: Ct);

        Assert.True(r.Success, r.Message);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(path)!));
        var item = Assert.Single(_q.List());
        Assert.Equal(QuarantineState.Isolated, item.State);
        Assert.Equal(path, item.OriginalPath);
        Assert.True(await _q.VerifyAsync(item.Id, Ct));

        // The payload must not contain the plaintext.
        var payload = Directory.GetFiles(Path.Combine(_store.Path, "q"), "*.bin").Single();
        Assert.True(File.ReadAllBytes(payload).AsSpan().IndexOf(TestFiles.Eicar) < 0);
        Assert.Contains(_log.ReadRecent(), e => e.Category == "quarantine" && e.Message.Contains("moved", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1024 * 1024)]
    [InlineData(1024 * 1024 + 1)]
    [InlineData(3 * 1024 * 1024 + 7)]
    public async Task Round_trip_preserves_content_for_chunk_boundaries(int size)
    {
        var data = new byte[size];
        Random.Shared.NextBytes(data);
        var path = _work.Write($"f{size}.bin", data);

        var r = await _q.QuarantineAsync(path, "X", "fake", Sha(data), ct: Ct);
        Assert.True(r.Success, r.Message);
        var restore = await _q.RestoreAsync(r.Item!.Id, new FakeEngine { MaxStreamBytes = long.MaxValue }, ct: Ct);

        Assert.True(restore.Success, restore.Message);
        Assert.Equal(data, File.ReadAllBytes(path));
        Assert.Empty(_q.List());
    }

    [Fact]
    public async Task Changed_file_is_not_quarantined()
    {
        var path = _work.Write("a.bin", "now different");
        var r = await _q.QuarantineAsync(path, "X", "fake", expectedSha256: TestFiles.EicarSha256, ct: Ct);
        Assert.False(r.Success);
        Assert.True(File.Exists(path));
        Assert.Empty(_q.List());
        Assert.Empty(Directory.GetFiles(Path.Combine(_store.Path, "q")));
    }

    [Fact]
    public async Task Symlinks_are_refused()
    {
        var target = _work.Write("real.bin", TestFiles.Eicar);
        var link = Path.Combine(_work.Path, "link.bin");
        File.CreateSymbolicLink(link, target);

        var r = await _q.QuarantineAsync(link, "X", "fake", null, ct: Ct);
        Assert.False(r.Success);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public async Task Protected_location_requires_admin_confirmation()
    {
        var path = _work.Write("system/core.dll", TestFiles.Eicar);
        var refused = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        Assert.False(refused.Success);
        Assert.Contains("Protected", refused.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(path));

        var confirmed = await _q.QuarantineAsync(path, "X", "fake", null, adminConfirmedProtectedFile: true, ct: Ct);
        Assert.True(confirmed.Success);
    }

    [Fact]
    public async Task Tampered_payload_is_detected_and_not_restored()
    {
        var path = _work.Write("t.bin", TestFiles.Eicar);
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        var payload = Directory.GetFiles(Path.Combine(_store.Path, "q"), "*.bin").Single();
        var bytes = File.ReadAllBytes(payload);
        bytes[10] ^= 0xFF;
        File.WriteAllBytes(payload, bytes);

        Assert.False(await _q.VerifyAsync(r.Item!.Id, Ct));
        var restore = await _q.RestoreAsync(r.Item.Id, new FakeEngine(), confirmedDespiteDetection: true, ct: Ct);
        Assert.False(restore.Success);
        Assert.Contains("Integrity", restore.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(_work.Path, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Truncated_payload_is_detected()
    {
        var data = new byte[3 * 1024 * 1024];
        Random.Shared.NextBytes(data);
        var path = _work.Write("big.bin", data);
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        var payload = Directory.GetFiles(Path.Combine(_store.Path, "q"), "*.bin").Single();

        // Cut exactly after the first full chunk: a chunk-aligned truncation.
        const int FirstChunk = 4 + 4 + 1024 * 1024 + 16;
        File.WriteAllBytes(payload, File.ReadAllBytes(payload)[..FirstChunk]);

        Assert.False(await _q.VerifyAsync(r.Item!.Id, Ct));
    }

    [Fact]
    public async Task Restore_still_detected_requires_confirmation()
    {
        var path = _work.Write("e.com", TestFiles.Eicar);
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);

        var refused = await _q.RestoreAsync(r.Item!.Id, new FakeEngine(), ct: Ct);
        Assert.False(refused.Success);
        Assert.Equal(Verdict.Infected, refused.RescanVerdict);
        Assert.False(File.Exists(path));
        Assert.Single(_q.List());

        var forced = await _q.RestoreAsync(r.Item.Id, new FakeEngine(), confirmedDespiteDetection: true, ct: Ct);
        Assert.True(forced.Success);
        Assert.Equal(TestFiles.Eicar, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task Restore_never_overwrites_existing_file()
    {
        var path = _work.Write("x.txt", "original");
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        File.WriteAllText(path, "new file at same place");

        var restore = await _q.RestoreAsync(r.Item!.Id, new FakeEngine(), ct: Ct);
        Assert.False(restore.Success);
        Assert.Equal("new file at same place", File.ReadAllText(path));
    }

    [Fact]
    public async Task Restore_refuses_target_through_symlinked_directory()
    {
        var path = _work.Write("dir/x.txt", "original");
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        using var elsewhere = new TempDir();
        Directory.Delete(Path.Combine(_work.Path, "dir"));
        Directory.CreateSymbolicLink(Path.Combine(_work.Path, "dir"), elsewhere.Path);

        var restore = await _q.RestoreAsync(r.Item!.Id, new FakeEngine(), ct: Ct);
        Assert.False(restore.Success);
        Assert.Contains("link", restore.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(elsewhere.Path));
    }

    [Fact]
    public async Task Restore_to_missing_directory_fails_cleanly()
    {
        var path = _work.Write("gone/x.txt", "data");
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        Directory.Delete(Path.Combine(_work.Path, "gone"));

        var restore = await _q.RestoreAsync(r.Item!.Id, new FakeEngine(), ct: Ct);
        Assert.False(restore.Success);
        Assert.Single(_q.List());
    }

    [Fact]
    public async Task Delete_requires_confirmation()
    {
        var path = _work.Write("d.bin", "data");
        var r = await _q.QuarantineAsync(path, "X", "fake", null, ct: Ct);
        Assert.False(_q.DeletePermanently(r.Item!.Id, userConfirmed: false));
        Assert.Single(_q.List());
        Assert.True(_q.DeletePermanently(r.Item.Id, userConfirmed: true));
        Assert.Empty(_q.List());
    }

    [Fact]
    public async Task Missing_file_and_quarantine_folder_itself_are_refused()
    {
        Assert.False((await _q.QuarantineAsync(Path.Combine(_work.Path, "nope"), "X", "fake", null, ct: Ct)).Success);
        var r = await _q.QuarantineAsync(_work.Write("y.bin", "data"), "X", "fake", null, ct: Ct);
        var payload = Directory.GetFiles(Path.Combine(_store.Path, "q"), "*.bin").Single();
        Assert.False((await _q.QuarantineAsync(payload, "X", "fake", null, ct: Ct)).Success);
        Assert.True(r.Success);
    }

    [Fact]
    public void Protection_policy_matches_only_whole_path_segments()
    {
        var root = Path.Combine(_work.Path, "Windows");
        var p = new ProtectedLocationsPolicy([root]);
        Assert.NotNull(p.GetProtectionReason(Path.Combine(root, "System32", "x.dll")));
        Assert.NotNull(p.GetProtectionReason(root));
        Assert.Null(p.GetProtectionReason(root + "Old" + Path.DirectorySeparatorChar + "x.dll"));
        Assert.Null(p.GetProtectionReason(Path.Combine(_work.Path, "Users", "x.dll")));
    }
}
