using UScan.Core.Engines;
using UScan.Core.Engines.ClamAV;
using UScan.Core.Model;

namespace UScan.Core.Tests.Unit;

public class ClamdResponseParserTests
{
    [Theory]
    [InlineData("stream: OK", Verdict.Clean, null)]
    [InlineData("stream: OK\0", Verdict.Clean, null)]
    [InlineData("stream: Win.Test.EICAR_HDB-1 FOUND", Verdict.Infected, "Win.Test.EICAR_HDB-1")]
    [InlineData("stream: UScan.Test.EICAR.UNOFFICIAL FOUND\n", Verdict.Infected, "UScan.Test.EICAR.UNOFFICIAL")]
    [InlineData("stream: Heuristics.Limits.Exceeded.MaxRecursion FOUND", Verdict.Incomplete, "Heuristics.Limits.Exceeded.MaxRecursion")]
    [InlineData("stream: Heuristics.Encrypted.Zip FOUND", Verdict.Incomplete, "Heuristics.Encrypted.Zip")]
    [InlineData("stream: Heuristics.Broken.Executable FOUND", Verdict.Suspicious, "Heuristics.Broken.Executable")]
    [InlineData("INSTREAM size limit exceeded. ERROR", Verdict.Error, null)]
    [InlineData("stream: Can't allocate memory ERROR", Verdict.Error, null)]
    [InlineData("", Verdict.Error, null)]
    [InlineData("garbage", Verdict.Error, null)]
    [InlineData("stream:  FOUND", Verdict.Error, null)]
    [InlineData("stream: something unexpected", Verdict.Error, null)]
    public void Scan_replies_map_to_verdicts(string reply, Verdict expected, string? name)
    {
        var r = ClamdResponseParser.ParseScanReply(reply);
        Assert.Equal(expected, r.Verdict);
        Assert.Equal(name, r.DetectionName);
        Assert.Equal("clamav", r.EngineId);
    }

    [Fact]
    public void Unknown_reply_is_never_clean()
    {
        foreach (var reply in new[] { "OK", "stream OK", "PONG", "stream: ok" })
        {
            Assert.NotEqual(Verdict.Clean, ClamdResponseParser.ParseScanReply(reply).Verdict);
        }
    }

    [Fact]
    public void Version_with_database()
    {
        var info = ClamdResponseParser.ParseVersion("ClamAV 1.5.4/27800/Wed Oct  7 08:23:45 2026\0");
        Assert.Equal("1.5.4", info.EngineVersion);
        Assert.Equal(27800, info.DatabaseVersion);
        Assert.NotNull(info.DatabaseTimestamp);
        Assert.Equal(new DateTime(2026, 10, 7, 8, 23, 45), info.DatabaseTimestamp!.Value.DateTime);
    }

    [Fact]
    public void Version_without_official_database_has_no_timestamp()
    {
        var info = ClamdResponseParser.ParseVersion("ClamAV 1.5.4 ");
        Assert.Equal("1.5.4", info.EngineVersion);
        Assert.Null(info.DatabaseVersion);
        Assert.Null(info.DatabaseTimestamp);
    }

    [Theory]
    [InlineData("")]
    [InlineData("PONG")]
    [InlineData("NotClamAV 1.0")]
    public void Unrecognised_version_throws(string reply) =>
        Assert.Throws<EngineUnavailableException>(() => ClamdResponseParser.ParseVersion(reply));
}
