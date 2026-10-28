namespace UScan.Core.Inventory;

public enum InventoryKind
{
    RegistryRun,
    StartupFolder,
    Service,
    ScheduledTask,
    WinlogonValue,
    ImageFileExecutionOptions,
    AppInitDll,
}

public enum SignatureStatus
{
    /// <summary>Embedded Authenticode signature verified against a trusted root.</summary>
    Valid,

    /// <summary>File hash is listed in a Windows security catalog whose signature verified.</summary>
    ValidCatalog,

    NotSigned,

    /// <summary>A signature exists but the file was modified after signing (hash mismatch).</summary>
    Invalid,

    /// <summary>Signature intact but chain untrusted, revoked, expired or explicitly distrusted.</summary>
    Untrusted,

    NotChecked,
    Error,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Signer, string? Detail)
{
    public bool IsTrusted => Status is SignatureStatus.Valid or SignatureStatus.ValidCatalog;
}

public interface ISignatureVerifier
{
    SignatureInfo Verify(string path);
}

/// <summary>Used where no Authenticode support exists (non-Windows hosts, tests).</summary>
public sealed class NoSignatureVerifier : ISignatureVerifier
{
    public SignatureInfo Verify(string path) => new(SignatureStatus.NotChecked, null, "Signature verification is only available on Windows.");
}

/// <summary>
/// One persistence entry (autostart, service, task …). Observations describe facts, they are
/// not malware verdicts: unknown or unsigned software is not automatically malicious.
/// </summary>
public sealed record InventoryEntry(
    InventoryKind Kind,
    string Location,
    string Name,
    string? Command,
    string? ImagePath,
    bool? FileExists,
    string? Sha256,
    SignatureInfo? Signature,
    IReadOnlyList<string> Observations);

public sealed record InventorySnapshot(DateTimeOffset TakenAt, IReadOnlyList<InventoryEntry> Entries, IReadOnlyList<string> Errors);

public interface IInventorySource
{
    string Name { get; }
    IEnumerable<InventoryEntry> Collect(ICollection<string> errors);
}
