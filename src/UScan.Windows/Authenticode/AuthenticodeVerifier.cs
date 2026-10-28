using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using UScan.Core.Inventory;

namespace UScan.Windows.Authenticode;

/// <summary>
/// Verifies Authenticode signatures with the documented WinVerifyTrust API: first the embedded
/// signature, then (for files without one, which includes most Windows system files) the
/// security catalogs via CryptCATAdmin*. Revocation is not checked online (no network access);
/// this is reported in <see cref="SignatureInfo.Detail"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    public SignatureInfo Verify(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        try
        {
            var embedded = NativeMethods.VerifyEmbedded(path);
            switch ((uint)embedded)
            {
                case 0:
                    return new SignatureInfo(SignatureStatus.Valid, GetEmbeddedSigner(path), "Embedded signature valid (revocation not checked online).");
                case NativeMethods.TRUST_E_NOSIGNATURE:
                case NativeMethods.TRUST_E_SUBJECT_FORM_UNKNOWN:
                case NativeMethods.TRUST_E_PROVIDER_UNKNOWN:
                    break; // no embedded signature → try catalogs
                default:
                    return Classify(embedded, GetEmbeddedSigner(path));
            }

            var catalog = NativeMethods.VerifyCatalog(path, out var catalogFile);
            if (catalogFile is null)
            {
                return new SignatureInfo(SignatureStatus.NotSigned, null, "No embedded signature and not listed in any security catalog.");
            }

            return catalog == 0
                ? new SignatureInfo(SignatureStatus.ValidCatalog, null, $"Listed in catalog {Path.GetFileName(catalogFile)}.")
                : Classify(catalog, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ExternalException)
        {
            return new SignatureInfo(SignatureStatus.Error, null, ex.Message);
        }
    }

    private static SignatureInfo Classify(int hr, string? signer) => (uint)hr switch
    {
        NativeMethods.TRUST_E_BAD_DIGEST =>
            new SignatureInfo(SignatureStatus.Invalid, signer, $"Hash mismatch (0x{hr:X8}): file was modified after signing."),
        NativeMethods.CERT_E_UNTRUSTEDROOT or NativeMethods.CERT_E_CHAINING or NativeMethods.TRUST_E_EXPLICIT_DISTRUST
            or NativeMethods.CERT_E_REVOKED or NativeMethods.CERT_E_EXPIRED or NativeMethods.TRUST_E_SUBJECT_NOT_TRUSTED
            or NativeMethods.CERT_E_UNTRUSTEDTESTROOT or NativeMethods.CRYPT_E_SECURITY_SETTINGS =>
            new SignatureInfo(SignatureStatus.Untrusted, signer, $"Signature present but not trusted (0x{hr:X8})."),
        _ => new SignatureInfo(SignatureStatus.Error, signer, $"WinVerifyTrust returned 0x{hr:X8}."),
    };

    private static string? GetEmbeddedSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the documented way to read the Authenticode signer certificate.
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using var cert2 = new X509Certificate2(cert);
            return cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or IOException)
        {
            return null;
        }
    }
}

[SupportedOSPlatform("windows")]
internal static class NativeMethods
{
    public const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    public const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    public const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
    public const uint TRUST_E_BAD_DIGEST = 0x80096010;
    public const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    public const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
    public const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    public const uint CERT_E_UNTRUSTEDTESTROOT = 0x800B010D;
    public const uint CERT_E_CHAINING = 0x800B010A;
    public const uint CERT_E_REVOKED = 0x800B010C;
    public const uint CERT_E_EXPIRED = 0x800B0101;
    public const uint CRYPT_E_SECURITY_SETTINGS = 0x80092026;

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

#pragma warning disable SYSLIB1054, CA5392 // classic marshalling is used for the by-value string struct; wintrust.dll is a System32 DLL
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
#pragma warning restore SYSLIB1054, CA5392

    public static int VerifyEmbedded(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pathPtr };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            return Run(WTD_CHOICE_FILE, filePtr);
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    /// <returns>WinVerifyTrust result; <paramref name="catalogFile"/> is null when no catalog lists the file.</returns>
    public static int VerifyCatalog(string path, out string? catalogFile)
    {
        catalogFile = null;
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        // Windows 10+ catalogs use SHA-256; older ones SHA-1 (null = default provider).
        foreach (var algorithm in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            {
                continue;
            }

            try
            {
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref size, null, 0);
                if (size == 0)
                {
                    continue;
                }

                var hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref size, hash, 0))
                {
                    continue;
                }

                var catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, size, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                {
                    continue;
                }

                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0))
                    {
                        continue;
                    }

                    catalogFile = info.wszCatalogFile;
                    var tag = Convert.ToHexString(hash);
                    var catPtr = Marshal.StringToHGlobalUni(catalogFile);
                    var tagPtr = Marshal.StringToHGlobalUni(tag);
                    var memberPtr = Marshal.StringToHGlobalUni(path);
                    var hashPtr = Marshal.AllocHGlobal(hash.Length);
                    var ci = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                    try
                    {
                        Marshal.Copy(hash, 0, hashPtr, hash.Length);
                        Marshal.StructureToPtr(new WINTRUST_CATALOG_INFO
                        {
                            cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                            pcwszCatalogFilePath = catPtr,
                            pcwszMemberTag = tagPtr,
                            pcwszMemberFilePath = memberPtr,
                            pbCalculatedFileHash = hashPtr,
                            cbCalculatedFileHash = (uint)hash.Length,
                            hCatAdmin = catAdmin,
                        }, ci, false);
                        return Run(WTD_CHOICE_CATALOG, ci);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ci);
                        Marshal.FreeHGlobal(hashPtr);
                        Marshal.FreeHGlobal(memberPtr);
                        Marshal.FreeHGlobal(tagPtr);
                        Marshal.FreeHGlobal(catPtr);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(catAdmin, 0);
            }
        }

        return unchecked((int)TRUST_E_NOSIGNATURE);
    }

    private static int Run(uint unionChoice, IntPtr union)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = union,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        };
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        var action = GenericVerifyV2;
        try
        {
            Marshal.StructureToPtr(data, dataPtr, false);
            var result = WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

            // Always release the state data allocated by the verify call.
            var after = Marshal.PtrToStructure<WINTRUST_DATA>(dataPtr);
            after.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(after, dataPtr, false);
            _ = WinVerifyTrust(IntPtr.Zero, ref action, dataPtr); // close result is irrelevant
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
        }
    }
}
