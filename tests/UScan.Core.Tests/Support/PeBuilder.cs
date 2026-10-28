using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;

namespace UScan.Core.Tests.Support;

/// <summary>
/// Builds small, non-functional PE32+ images with chosen section flags, entry point and imports.
/// The files contain no code that could run; they only exercise the static analyzer.
/// </summary>
internal sealed class PeBuilder
{
    private readonly List<(string Name, SectionCharacteristics Flags, byte[] Data)> _sections = [];
    private readonly List<string> _imports = [];
    private int _entrySection;
    private uint _timestamp = 0x60000000; // 2021

    public PeBuilder Section(string name, SectionCharacteristics flags, byte[]? data = null)
    {
        _sections.Add((name, flags, data ?? new byte[0x200]));
        return this;
    }

    public PeBuilder Imports(params string[] functions)
    {
        _imports.AddRange(functions);
        return this;
    }

    public PeBuilder EntryIn(int sectionIndex)
    {
        _entrySection = sectionIndex;
        return this;
    }

    public PeBuilder Timestamp(DateTimeOffset t)
    {
        _timestamp = (uint)t.ToUnixTimeSeconds();
        return this;
    }

    public static SectionCharacteristics Code => SectionCharacteristics.ContainsCode | SectionCharacteristics.MemExecute | SectionCharacteristics.MemRead;
    public static SectionCharacteristics Data => SectionCharacteristics.ContainsInitializedData | SectionCharacteristics.MemRead;
    public static SectionCharacteristics Rwx => Code | SectionCharacteristics.MemWrite;

    public static byte[] RandomBytes(int n, int seed = 1)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }

    public byte[] Build()
    {
        var sections = new List<(string Name, SectionCharacteristics Flags, byte[] Data)>(_sections);
        var importSectionIndex = -1;
        if (_imports.Count > 0)
        {
            importSectionIndex = sections.Count;
            sections.Add((".idata", Data | SectionCharacteristics.MemWrite, []));
        }

        const int FileAlign = 0x200, SectAlign = 0x1000;
        var headerSize = Align(0x40 + 4 + 20 + 240 + 40 * sections.Count, FileAlign);
        // Import data size is known up front: compute it once to lay out virtual addresses without overlap.
        var importSize = _imports.Count > 0 ? BuildImports(0).Length : 0;
        var vas = new uint[sections.Count];
        uint nextVa = SectAlign;
        for (var i = 0; i < sections.Count; i++)
        {
            vas[i] = nextVa;
            var size = i == importSectionIndex ? importSize : sections[i].Data.Length;
            nextVa += (uint)Align(Math.Max(size, 1), SectAlign);
        }


        if (importSectionIndex >= 0)
        {
            sections[importSectionIndex] = (".idata", sections[importSectionIndex].Flags, BuildImports(vas[importSectionIndex]));
        }

        var raw = sections.Select(s => Align(Math.Max(s.Data.Length, 1), FileAlign)).ToArray();
        var total = headerSize + raw.Sum();
        var pe = new byte[total];
        var span = pe.AsSpan();

        span[0] = (byte)'M';
        span[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(span[0x3C..], 0x40);
        "PE\0\0"u8.CopyTo(span[0x40..]);

        var coff = span[0x44..];
        BinaryPrimitives.WriteUInt16LittleEndian(coff, 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[2..], (ushort)sections.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(coff[4..], _timestamp);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[16..], 240);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[18..], 0x0022);

        var opt = span[(0x44 + 20)..];
        BinaryPrimitives.WriteUInt16LittleEndian(opt, 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[16..], vas[_entrySection] + 0x10);
        BinaryPrimitives.WriteUInt64LittleEndian(opt[24..], 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[32..], SectAlign);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[36..], FileAlign);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[40..], 6);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[48..], 6);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[56..], nextVa);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[60..], (uint)headerSize);
        BinaryPrimitives.WriteUInt16LittleEndian(opt[68..], 3);
        BinaryPrimitives.WriteUInt32LittleEndian(opt[108..], 16);
        if (importSectionIndex >= 0)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(opt[(112 + 8)..], vas[importSectionIndex]);
            BinaryPrimitives.WriteUInt32LittleEndian(opt[(112 + 12)..], 40);
        }

        var pointer = headerSize;
        for (var i = 0; i < sections.Count; i++)
        {
            var sh = span[(0x44 + 20 + 240 + 40 * i)..];
            var name = Encoding.ASCII.GetBytes(sections[i].Name);
            name.AsSpan(0, Math.Min(8, name.Length)).CopyTo(sh);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[8..], (uint)Math.Max(sections[i].Data.Length, 1));
            BinaryPrimitives.WriteUInt32LittleEndian(sh[12..], vas[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[16..], (uint)raw[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[20..], (uint)pointer);
            BinaryPrimitives.WriteUInt32LittleEndian(sh[36..], (uint)sections[i].Flags);
            sections[i].Data.CopyTo(span[pointer..]);
            pointer += raw[i];
        }

        return pe;
    }

    private byte[] BuildImports(uint va)
    {
        // descriptor[2] | ILT (n+1)*8 | IAT (n+1)*8 | hint/name entries | dll name
        var n = _imports.Count;
        var ilt = 40;
        var iat = ilt + (n + 1) * 8;
        var names = iat + (n + 1) * 8;
        using var ms = new MemoryStream();
        var nameOffsets = new List<int>();
        var cursor = names;
        foreach (var f in _imports)
        {
            nameOffsets.Add(cursor);
            cursor += 2 + f.Length + 1;
        }

        var dllName = cursor;
        var buf = new byte[dllName + "kernel32.dll".Length + 1];
        var s = buf.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s, va + (uint)ilt);
        BinaryPrimitives.WriteUInt32LittleEndian(s[12..], va + (uint)dllName);
        BinaryPrimitives.WriteUInt32LittleEndian(s[16..], va + (uint)iat);
        for (var i = 0; i < n; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(s[(ilt + i * 8)..], va + (uint)nameOffsets[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(s[(iat + i * 8)..], va + (uint)nameOffsets[i]);
            Encoding.ASCII.GetBytes(_imports[i]).CopyTo(s[(nameOffsets[i] + 2)..]);
        }

        "kernel32.dll"u8.CopyTo(s[dllName..]);
        return buf;
    }

    private static int Align(int v, int a) => (v + a - 1) / a * a;
}
