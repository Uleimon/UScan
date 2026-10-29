using System.Security.Cryptography;
using System.Text;
using UScan.Core.App;
using UScan.Core.Model;
using UScan.Core.Storage;
using UScan.Core.Tests.Support;

namespace UScan.Core.Tests.Unit;

public class HostAllowTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static (UScanHost Host, string File) HostWithDetection(TempDir dir, string content)
    {
        var host = new UScanHost(new AppPaths(Path.Combine(dir.Path, "data")), new GenericPlatformServices());
        var file = dir.Write("found.exe", content);
        var sha = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
        host.Reports.Save(new ScanReport(Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, ScanOutcome.Completed, [dir.Path], null, 1,
            [new FileScanResult(file, content.Length, sha, Verdict.Infected, SkipReason.None, [new EngineResult(Verdict.Infected, "clamav", "Test.Sig", null)], null, TimeSpan.Zero)], []));
        return (host, file);
    }

    [Fact]
    public void Allowing_an_unchanged_file_closes_the_detection_and_is_logged()
    {
        using var dir = new TempDir();
        var (host, file) = HostWithDetection(dir, "payload");
        Assert.Single(host.OpenDetections());

        Assert.Null(host.AllowOpenDetection(file, "false positive"));

        Assert.Empty(host.OpenDetections());
        Assert.Single(host.AllowList());
        Assert.Contains(host.Log.ReadRecent(10), e => e.Category == "allowlist" && e.Path == file);
    }

    [Fact]
    public async Task A_file_changed_after_the_scan_is_not_allowed()
    {
        using var dir = new TempDir();
        var (host, file) = HostWithDetection(dir, "payload");
        await File.WriteAllTextAsync(file, "different", Ct);

        Assert.Contains("changed", host.AllowOpenDetection(file, "false positive"), StringComparison.Ordinal);
        Assert.Empty(host.AllowList());
    }

    [Fact]
    public void A_reason_is_required_and_unknown_files_are_refused()
    {
        using var dir = new TempDir();
        var (host, file) = HostWithDetection(dir, "payload");

        Assert.NotNull(host.AllowOpenDetection(file, " "));
        Assert.NotNull(host.AllowOpenDetection(Path.Combine(dir.Path, "other.exe"), "x"));
        Assert.Single(host.OpenDetections());
    }
}
