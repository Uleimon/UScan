using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;
using UScan.Core.Inventory;

namespace UScan.Core.Heuristics;

public sealed record PeSection(string Name, SectionCharacteristics Characteristics, double Entropy, int RawSize)
{
    public bool IsExecutable => Characteristics.HasFlag(SectionCharacteristics.MemExecute) || Characteristics.HasFlag(SectionCharacteristics.ContainsCode);
    public bool IsWritable => Characteristics.HasFlag(SectionCharacteristics.MemWrite);
}

/// <summary>Facts extracted from a PE file; scoring is separate so it can be tested with hand-made facts.</summary>
public sealed record PeFacts(
    bool Is64Bit,
    bool IsDll,
    bool IsManaged,
    DateTimeOffset? Timestamp,
    IReadOnlyList<PeSection> Sections,
    string? EntryPointSection,
    bool EntryPointInExecutableSection,
    IReadOnlyList<string> ImportedFunctions,
    long OverlayBytes,
    long FileBytes);

/// <summary>Static PE analysis: reads headers, sections and import names only; never executes or loads the file.</summary>
public sealed class PeAnalyzer : IHeuristicAnalyzer
{
    private static readonly string[] PackerSections = ["UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", "MPRESS1", "MPRESS2", ".nsp0", ".nsp1", ".themida", ".vmp0", ".vmp1", ".enigma1"];
    private static readonly string[] ExecutableExtensions = [".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx"];
    private static readonly string[] DocumentLikeExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip", ".rtf"];

    private readonly ISignatureVerifier _signatures;
    private readonly TimeProvider _time;

    public PeAnalyzer(ISignatureVerifier? signatures = null, TimeProvider? time = null)
    {
        _signatures = signatures ?? new NoSignatureVerifier();
        _time = time ?? TimeProvider.System;
    }

    public const int MaxBytes = 64 * 1024 * 1024;

    public bool CanAnalyze(string path, ReadOnlySpan<byte> header) => header.Length >= 2 && header[0] == (byte)'M' && header[1] == (byte)'Z';

    public HeuristicResult Analyze(string path, Stream content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var features = new List<HeuristicFeature>();
        AddContextFeatures(path, features);

        PeFacts? facts;
        try
        {
            facts = Extract(content);
        }
        catch (InvalidDataException)
        {
            return HeuristicResult.None; // too large: not analysed, not judged
        }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentOutOfRangeException or InvalidOperationException)
        {
            facts = null;
        }

        if (facts is null)
        {
            if (ExecutableExtensions.Contains(Path.GetExtension(path).ToLowerInvariant()))
            {
                features.Add(new("pe.malformed", 10, "Executable file with a malformed PE structure."));
            }

            return HeuristicScorer.Score(features);
        }

        features.AddRange(Evaluate(facts, _time.GetUtcNow()));

        var sig = _signatures.Verify(path);
        switch (sig.Status)
        {
            case SignatureStatus.Valid:
            case SignatureStatus.ValidCatalog:
                features.Add(new("sig.trusted", -50, $"Trusted digital signature{(sig.Signer is null ? "" : $" ({sig.Signer})")}."));
                break;
            case SignatureStatus.Invalid:
                features.Add(new("sig.invalid", 35, "Digital signature is invalid: the file was modified after signing."));
                break;
            case SignatureStatus.NotSigned:
                features.Add(new("sig.none", 10, "Not digitally signed."));
                break;
        }

        return HeuristicScorer.Score(features);
    }

    internal static IEnumerable<HeuristicFeature> Evaluate(PeFacts f, DateTimeOffset now)
    {
        var wx = f.Sections.FirstOrDefault(s => s.IsExecutable && s.IsWritable);
        if (wx is not null)
        {
            yield return new("pe.wx", 25, $"Section '{wx.Name}' is both writable and executable (typical for unpacking or self-modifying code).");
        }

        var packer = f.Sections.FirstOrDefault(s => PackerSections.Contains(s.Name, StringComparer.OrdinalIgnoreCase));
        if (packer is not null)
        {
            yield return new("pe.packer", 15, $"Section name '{packer.Name}' belongs to a known packer/protector (packing alone is not malicious).");
        }

        var entropic = f.Sections.FirstOrDefault(s => s.IsExecutable && s.RawSize > 4096 && s.Entropy > 7.2);
        if (entropic is not null)
        {
            yield return new("pe.entropy", 15, $"Executable section '{entropic.Name}' has very high entropy ({entropic.Entropy:F2}), indicating compressed or encrypted code.");
        }

        if (!f.IsManaged && !f.IsDll && !f.EntryPointInExecutableSection)
        {
            yield return new("pe.ep", 20, f.EntryPointSection is null
                ? "Entry point lies outside every section."
                : $"Entry point lies in non-executable section '{f.EntryPointSection}'.");
        }

        var imports = new HashSet<string>(f.ImportedFunctions, StringComparer.OrdinalIgnoreCase);
        if (!f.IsManaged && imports.Count is > 0 and < 6 && imports.Contains("GetProcAddress") && (imports.Contains("LoadLibraryA") || imports.Contains("LoadLibraryW") || imports.Contains("LoadLibraryExA") || imports.Contains("LoadLibraryExW")))
        {
            yield return new("pe.dynimports", 15, "Imports almost nothing except LoadLibrary/GetProcAddress (APIs resolved at runtime, common in packed code).");
        }

        if (imports.Contains("WriteProcessMemory") && (imports.Contains("CreateRemoteThread") || imports.Contains("CreateRemoteThreadEx") || imports.Contains("QueueUserAPC") || imports.Contains("NtQueueApcThread"))
            && (imports.Contains("VirtualAllocEx") || imports.Contains("NtAllocateVirtualMemory")))
        {
            yield return new("pe.injection", 30, "Imports the API combination used to inject code into other processes (also used by debuggers and some legitimate tools).");
        }

        if (imports.Contains("SetWindowsHookExA") || imports.Contains("SetWindowsHookExW"))
        {
            if (imports.Contains("GetAsyncKeyState") || imports.Contains("GetKeyboardState"))
            {
                yield return new("pe.keyhook", 20, "Imports keyboard hook and key state APIs (keylogging-capable; also used by hotkey tools).");
            }
        }

        if (f.Timestamp is { } ts && ts > now.AddDays(2) && ts.Year < 2100)
        {
            yield return new("pe.timestamp", 5, $"Compile timestamp lies in the future ({ts:yyyy-MM-dd}).");
        }

        if (f.FileBytes > 0 && f.OverlayBytes > f.FileBytes / 2 && f.OverlayBytes > 1024 * 1024)
        {
            yield return new("pe.overlay", 10, $"More than half of the file ({f.OverlayBytes} bytes) is appended data outside the PE image (common for installers and droppers).");
        }
    }

    private static void AddContextFeatures(string path, List<HeuristicFeature> features)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        var ext = Path.GetExtension(name);
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(name));
        if (ExecutableExtensions.Contains(ext) && DocumentLikeExtensions.Contains(inner))
        {
            features.Add(new("ctx.doubleext", 25, $"Double extension '{inner}{ext}' disguises an executable as a document."));
        }

        var normalized = path.Replace('/', '\\');
        if (normalized.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
        {
            features.Add(new("ctx.location", 5, "Located in a download or temporary folder."));
        }
    }

    public static PeFacts? Extract(Stream content)
    {
        var data = ReadAll(content);
        using var reader = new PEReader(new MemoryStream(data, writable: false));
        var headers = reader.PEHeaders;
        var pe = headers.PEHeader;
        if (pe is null)
        {
            return null;
        }

        var sections = new List<PeSection>();
        string? epSection = null;
        var epExec = false;
        long imageEnd = headers.PEHeaderStartOffset;
        foreach (var s in headers.SectionHeaders)
        {
            var start = s.PointerToRawData;
            var size = (int)Math.Max(0, Math.Min(s.SizeOfRawData, data.Length - (long)start));
            var section = new PeSection(s.Name, s.SectionCharacteristics, start < data.Length ? Entropy(data.AsSpan(start, size)) : 0, size);
            sections.Add(section);
            imageEnd = Math.Max(imageEnd, (long)start + s.SizeOfRawData);
            var rva = pe.AddressOfEntryPoint;
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
            {
                epSection = s.Name;
                epExec = section.IsExecutable;
            }
        }

        var cert = pe.CertificateTableDirectory;
        long overlay = Math.Max(0, data.Length - imageEnd - (cert.Size > 0 ? cert.Size : 0));
        var ts = headers.CoffHeader.TimeDateStamp;

        return new PeFacts(
            pe.Magic == PEMagic.PE32Plus,
            headers.IsDll,
            headers.CorHeader is not null,
            ts == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(ts),
            sections,
            epSection,
            epExec,
            ReadImports(data, headers),
            overlay,
            data.Length);
    }

    private static List<string> ReadImports(byte[] data, PEHeaders headers)
    {
        var result = new List<string>();
        var dir = headers.PEHeader!.ImportTableDirectory;
        if (dir.Size == 0 || dir.RelativeVirtualAddress == 0)
        {
            return result;
        }

        var is64 = headers.PEHeader.Magic == PEMagic.PE32Plus;
        var descOffset = RvaToOffset(headers, dir.RelativeVirtualAddress);
        for (var d = 0; d < 512 && descOffset >= 0 && descOffset + 20 <= data.Length; d++, descOffset += 20)
        {
            var desc = data.AsSpan(descOffset, 20);
            var originalThunk = BinaryPrimitives.ReadInt32LittleEndian(desc);
            var nameRva = BinaryPrimitives.ReadInt32LittleEndian(desc[12..]);
            var firstThunk = BinaryPrimitives.ReadInt32LittleEndian(desc[16..]);
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                break;
            }

            var thunk = RvaToOffset(headers, originalThunk != 0 ? originalThunk : firstThunk);
            var step = is64 ? 8 : 4;
            for (var t = 0; t < 8192 && thunk >= 0 && thunk + step <= data.Length; t++, thunk += step)
            {
                var value = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(thunk)) : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(thunk));
                if (value == 0)
                {
                    break;
                }

                var byOrdinal = is64 ? (value & 0x8000000000000000UL) != 0 : (value & 0x80000000UL) != 0;
                if (byOrdinal || value > int.MaxValue)
                {
                    continue;
                }

                var nameOffset = RvaToOffset(headers, (int)value);
                if (nameOffset < 0 || nameOffset + 2 >= data.Length)
                {
                    continue;
                }

                var start = nameOffset + 2;
                var end = Array.IndexOf(data, (byte)0, start, Math.Min(256, data.Length - start));
                if (end > start)
                {
                    result.Add(Encoding.ASCII.GetString(data, start, end - start));
                }
            }
        }

        return result;
    }

    private static int RvaToOffset(PEHeaders headers, int rva)
    {
        foreach (var s in headers.SectionHeaders)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
            {
                return rva - s.VirtualAddress + s.PointerToRawData;
            }
        }

        return -1;
    }

    internal static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double e = 0;
        foreach (var c in counts)
        {
            if (c > 0)
            {
                var p = (double)c / data.Length;
                e -= p * Math.Log2(p);
            }
        }

        return e;
    }

    private static byte[] ReadAll(Stream s)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int n;
        while ((n = s.Read(buffer)) > 0)
        {
            if (ms.Length + n > MaxBytes)
            {
                throw new InvalidDataException("File too large for heuristic analysis.");
            }

            ms.Write(buffer, 0, n);
        }

        return ms.ToArray();
    }
}
