using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using UScan.Core.Storage;

namespace UScan.Core.Updates;

public sealed record UpdatePackage(string FileName, string Sha256, long Size);

/// <summary>Signed description of one release. Signed bytes are the exact manifest file; the signature is detached.</summary>
public sealed record UpdateManifest(
    string Product,
    string Channel,
    string Version,
    DateTimeOffset PublishedAt,
    DateTimeOffset ExpiresAt,
    string KeyId,
    UpdatePackage Package);

public sealed record UpdateCheck(bool Accepted, UpdateManifest? Manifest, string Reason);

/// <summary>
/// Verifies update manifests before anything is downloaded or executed:
/// ECDSA P-256 / SHA-256 signature by a pinned public key, product and channel match,
/// version strictly newer than the installed one (downgrade and replay protection),
/// not expired (freeze protection) and not dated in the future. Only public keys are
/// embedded in the client; the private key never leaves the release environment.
/// </summary>
public sealed class UpdateVerifier
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IReadOnlyDictionary<string, ECDsa> _trustedKeys;
    private readonly Version _installed;
    private readonly string _channel;
    private readonly TimeProvider _time;

    public const string ProductName = "UScan";

    public UpdateVerifier(IReadOnlyDictionary<string, ECDsa> trustedKeys, Version installedVersion, string channel = "stable", TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);
        ArgumentNullException.ThrowIfNull(installedVersion);
        _trustedKeys = trustedKeys;
        _installed = installedVersion;
        _channel = channel;
        _time = time ?? TimeProvider.System;
    }

    public static ECDsa LoadPublicKey(string pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        if (key.KeySize != 256)
        {
            key.Dispose();
            throw new CryptographicException("Only P-256 keys are accepted.");
        }

        return key;
    }

    public UpdateCheck Verify(ReadOnlySpan<byte> manifestBytes, ReadOnlySpan<byte> signature)
    {
        if (manifestBytes.Length > 64 * 1024)
        {
            return Reject("Manifest too large.");
        }

        UpdateManifest? m;
        try
        {
            m = JsonSerializer.Deserialize<UpdateManifest>(manifestBytes, Json);
        }
        catch (JsonException ex)
        {
            return Reject($"Manifest is not valid JSON: {ex.Message}");
        }

        if (m is null || m.Package is null || string.IsNullOrEmpty(m.KeyId))
        {
            return Reject("Manifest is incomplete.");
        }

        if (!_trustedKeys.TryGetValue(m.KeyId, out var key))
        {
            return Reject($"Manifest is signed with unknown key '{m.KeyId}'.");
        }

        if (!key.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256))
        {
            return Reject("Signature verification failed.");
        }

        // Only checked after the signature: unsigned content must not influence decisions.
        if (m.Product != ProductName || m.Channel != _channel)
        {
            return Reject($"Manifest is for '{m.Product}/{m.Channel}', expected '{ProductName}/{_channel}'.");
        }

        if (!Version.TryParse(m.Version, out var offered))
        {
            return Reject("Invalid version number.");
        }

        if (offered <= _installed)
        {
            return Reject($"Offered version {offered} is not newer than installed {_installed} (downgrade/replay rejected).");
        }

        var now = _time.GetUtcNow();
        if (m.ExpiresAt <= now)
        {
            return Reject($"Manifest expired at {m.ExpiresAt:u} (possible freeze attack or stale mirror).");
        }

        if (m.PublishedAt > now.AddMinutes(10))
        {
            return Reject("Manifest is dated in the future.");
        }

        if (m.Package.Size <= 0 || m.Package.Sha256.Length != 64 || m.Package.FileName.IndexOfAny(['/', '\\']) >= 0)
        {
            return Reject("Package description is invalid.");
        }

        return new UpdateCheck(true, m, $"Version {offered} verified.");

        static UpdateCheck Reject(string reason) => new(false, null, reason);
    }

    /// <summary>Checks a downloaded package against the signed size and SHA-256 before it is opened.</summary>
    public static bool VerifyPackage(Stream package, UpdatePackage expected, out string reason)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(expected);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int n;
        while ((n = package.Read(buffer)) > 0)
        {
            total += n;
            if (total > expected.Size)
            {
                reason = "Package is larger than declared.";
                return false;
            }

            sha.AppendData(buffer, 0, n);
        }

        if (total != expected.Size)
        {
            reason = $"Package size {total} differs from signed size {expected.Size}.";
            return false;
        }

        var actual = Convert.ToHexStringLower(sha.GetHashAndReset());
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(expected.Sha256.ToLowerInvariant())))
        {
            reason = "Package SHA-256 does not match the signed manifest.";
            return false;
        }

        reason = "Package verified.";
        return true;
    }
}

public sealed record InstallResult(bool Success, string Message, string? ActiveVersion);

/// <summary>
/// Side-by-side installation: versions/&lt;v&gt;/ plus an atomically replaced pointer file.
/// The previous version stays on disk, so a failed self-test or a later problem can be rolled back.
/// </summary>
public sealed class StagedInstaller
{
    private readonly string _root;
    private readonly long _maxExtractedBytes;
    private readonly int _maxEntries;

    public StagedInstaller(string root, long maxExtractedBytes = 1024L * 1024 * 1024, int maxEntries = 20_000)
    {
        _root = Directory.CreateDirectory(root).FullName;
        _maxExtractedBytes = maxExtractedBytes;
        _maxEntries = maxEntries;
        Directory.CreateDirectory(VersionsDir);
    }

    private string VersionsDir => Path.Combine(_root, "versions");
    private string CurrentFile => Path.Combine(_root, "current.txt");
    private string PreviousFile => Path.Combine(_root, "previous.txt");

    public string? ActiveVersion => File.Exists(CurrentFile) ? File.ReadAllText(CurrentFile).Trim() : null;

    public string? ActiveDirectory => ActiveVersion is { } v ? Path.Combine(VersionsDir, v) : null;

    /// <param name="verifiedZip">Must already have passed <see cref="UpdateVerifier.VerifyPackage"/>.</param>
    /// <param name="version">Version from the verified manifest.</param>
    /// <param name="selfTest">Runs against the extracted directory; the switch happens only if it returns true.</param>
    public InstallResult Install(Stream verifiedZip, Version version, Func<string, bool> selfTest)
    {
        ArgumentNullException.ThrowIfNull(verifiedZip);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentNullException.ThrowIfNull(selfTest);
        var name = version.ToString();
        var target = Path.Combine(VersionsDir, name);
        if (Directory.Exists(target))
        {
            return new InstallResult(false, $"Version {name} is already installed.", ActiveVersion);
        }

        var staging = target + ".staging-" + Guid.NewGuid().ToString("N");
        try
        {
            Extract(verifiedZip, staging);
            if (!selfTest(staging))
            {
                Directory.Delete(staging, recursive: true);
                return new InstallResult(false, "Self-test of the new version failed; the current version stays active.", ActiveVersion);
            }

            Directory.Move(staging, target);
            var previous = ActiveVersion;
            if (previous is not null)
            {
                AtomicFile.WriteAllBytes(PreviousFile, System.Text.Encoding.UTF8.GetBytes(previous));
            }

            AtomicFile.WriteAllBytes(CurrentFile, System.Text.Encoding.UTF8.GetBytes(name));
            return new InstallResult(true, $"Version {name} is now active.", name);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }

            return new InstallResult(false, $"Installation failed: {ex.Message}", ActiveVersion);
        }
    }

    public InstallResult Rollback()
    {
        if (!File.Exists(PreviousFile))
        {
            return new InstallResult(false, "No previous version recorded.", ActiveVersion);
        }

        var previous = File.ReadAllText(PreviousFile).Trim();
        if (!Directory.Exists(Path.Combine(VersionsDir, previous)))
        {
            return new InstallResult(false, $"Previous version {previous} is no longer on disk.", ActiveVersion);
        }

        var current = ActiveVersion;
        AtomicFile.WriteAllBytes(CurrentFile, System.Text.Encoding.UTF8.GetBytes(previous));
        if (current is not null)
        {
            AtomicFile.WriteAllBytes(PreviousFile, System.Text.Encoding.UTF8.GetBytes(current));
        }

        return new InstallResult(true, $"Rolled back to {previous}.", previous);
    }

    /// <summary>Extraction with protection against path traversal ("zip slip"), links, and size/entry bombs.</summary>
    private void Extract(Stream zipStream, string destination)
    {
        var root = Path.GetFullPath(Directory.CreateDirectory(destination).FullName) + Path.DirectorySeparatorChar;
        using var zip = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count > _maxEntries)
        {
            throw new InvalidDataException("Package has too many entries.");
        }

        long total = 0;
        foreach (var e in zip.Entries)
        {
            var full = Path.GetFullPath(Path.Combine(root, e.FullName));
            if (!full.StartsWith(root, StringComparison.Ordinal) || Path.IsPathRooted(e.FullName))
            {
                throw new InvalidDataException($"Entry '{e.FullName}' would be written outside the installation directory.");
            }

            // Unix symlink entries carry S_IFLNK in the upper external-attribute bits.
            if (((e.ExternalAttributes >> 16) & 0xF000) == 0xA000)
            {
                throw new InvalidDataException($"Entry '{e.FullName}' is a symbolic link.");
            }

            if (e.FullName.EndsWith('/') || e.FullName.EndsWith('\\'))
            {
                Directory.CreateDirectory(full);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            using var input = e.Open();
            using var output = new FileStream(full, FileMode.CreateNew, FileAccess.Write);
            var buffer = new byte[81920];
            int n;
            while ((n = input.Read(buffer)) > 0)
            {
                total += n;
                if (total > _maxExtractedBytes)
                {
                    throw new InvalidDataException("Package expands beyond the allowed size.");
                }

                output.Write(buffer, 0, n);
            }
        }
    }
}
