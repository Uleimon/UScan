using System.IO.Compression;
using System.Text;

namespace UScan.Core.Tests.Support;

/// <summary>
/// Harmless test content only. The EICAR string is assembled at runtime so that the
/// source file itself is not flagged by the developer's own antivirus.
/// See https://www.eicar.org/download-anti-malware-testfile/.
/// </summary>
internal static class TestFiles
{
    public static readonly byte[] Eicar = Encoding.ASCII.GetBytes(
        string.Concat(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS", "-TEST-FILE!$H+H*"));

    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    public const string EicarMd5 = "44d88612fea8a8f36de82e1278abb02f";

    public static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                var e = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var s = e.Open();
                s.Write(data);
            }
        }

        return ms.ToArray();
    }

    public static byte[] NestedZip(byte[] innermost, string innermostName, int levels)
    {
        var data = innermost;
        var name = innermostName;
        for (var i = 0; i < levels; i++)
        {
            data = Zip((name, data));
            name = $"level{i}.zip";
        }

        return data;
    }

    public static byte[] ZipWithZeros(long size)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = zip.CreateEntry("zeros.bin", CompressionLevel.Optimal).Open();
            var chunk = new byte[1024 * 1024];
            for (long written = 0; written < size; written += chunk.Length)
            {
                s.Write(chunk, 0, (int)Math.Min(chunk.Length, size - written));
            }
        }

        return ms.ToArray();
    }
}

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = Directory.CreateTempSubdirectory("uscan-test-").FullName;
    }

    public string Path { get; }

    public string Write(string relative, byte[] data)
    {
        var full = System.IO.Path.GetFullPath(System.IO.Path.Combine(Path, relative));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, data);
        return full;
    }

    public string Write(string relative, string text) => Write(relative, Encoding.UTF8.GetBytes(text));

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
