using System.Management;
using System.Runtime.Versioning;

namespace UScan.Windows.Defender;

/// <summary>Microsoft Defender state as reported by its documented WMI class MSFT_MpComputerStatus (read-only).</summary>
public sealed record DefenderStatus(
    bool Available,
    bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled,
    bool? TamperProtected,
    string? SignatureVersion,
    DateTimeOffset? SignatureLastUpdated,
    string? Error);

[SupportedOSPlatform("windows")]
public static class DefenderStatusProvider
{
    public static DefenderStatus Query()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
            foreach (var o in searcher.Get().Cast<ManagementObject>())
            {
                using (o)
                {
                    return new DefenderStatus(
                        true,
                        o["AntivirusEnabled"] as bool?,
                        o["RealTimeProtectionEnabled"] as bool?,
                        o["IsTamperProtected"] as bool?,
                        o["AntivirusSignatureVersion"] as string,
                        o["AntivirusSignatureLastUpdated"] is string dmtf ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(dmtf)) : null,
                        null);
                }
            }

            return new DefenderStatus(false, null, null, null, null, null, "MSFT_MpComputerStatus returned no instance.");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException or PlatformNotSupportedException)
        {
            return new DefenderStatus(false, null, null, null, null, null, ex.Message);
        }
    }
}
