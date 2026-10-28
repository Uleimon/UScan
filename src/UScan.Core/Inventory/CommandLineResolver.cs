namespace UScan.Core.Inventory;

public sealed record ResolvedCommand(string? Executable, string? Target, IReadOnlyList<string> Observations);

/// <summary>
/// Extracts the file that actually runs from an autostart/service command line, e.g.
/// <c>"C:\Program Files\App\app.exe" -bg</c>, <c>C:\Program Files\App\app.exe -bg</c> (unquoted with spaces),
/// <c>%SystemRoot%\system32\svchost.exe -k netsvcs</c>, <c>rundll32.exe C:\x\y.dll,Entry</c>.
/// For script and proxy hosts the script/DLL argument is reported as <see cref="ResolvedCommand.Target"/>.
/// Pure string logic plus an injectable file-exists check, so it is fully testable on any OS.
/// </summary>
public sealed class CommandLineResolver
{
    private static readonly string[] ScriptHosts = ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"];
    private static readonly string[] ProxyHosts = ["rundll32.exe", "regsvr32.exe"];
    private static readonly string[] ScriptExtensions = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"];

    private readonly Func<string, bool> _fileExists;
    private readonly IReadOnlyList<string> _searchDirs;
    private readonly Func<string, string> _expand;

    public CommandLineResolver(Func<string, bool>? fileExists = null, IReadOnlyList<string>? searchDirs = null, Func<string, string>? expandEnvironment = null)
    {
        _fileExists = fileExists ?? File.Exists;
        _searchDirs = searchDirs ?? DefaultSearchDirs();
        _expand = expandEnvironment ?? Environment.ExpandEnvironmentVariables;
    }

    public ResolvedCommand Resolve(string? commandLine)
    {
        var notes = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return new ResolvedCommand(null, null, ["Empty command."]);
        }

        var cmd = _expand(commandLine.Trim());
        if (cmd.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            cmd = cmd[4..];
        }
        else if (cmd.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            cmd = _expand("%SystemRoot%") + cmd[@"\SystemRoot".Length..];
        }

        string exe;
        string rest;
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            if (end < 0)
            {
                return new ResolvedCommand(null, null, ["Unbalanced quotes in command line."]);
            }

            exe = cmd[1..end];
            rest = cmd[(end + 1)..].Trim();
        }
        else
        {
            (exe, rest) = SplitUnquoted(cmd, notes);
        }

        exe = Qualify(exe);
        var name = exe[(exe.LastIndexOfAny(['\\', '/']) + 1)..].ToLowerInvariant();
        string? target = null;

        if (ProxyHosts.Contains(name))
        {
            var arg = FirstArgument(rest);
            if (arg is not null)
            {
                var dll = arg.Split(',')[0].Trim();
                if (dll.Length > 0)
                {
                    target = Qualify(dll);
                    notes.Add($"Runs code from '{target}' through {name}.");
                }
            }
        }
        else if (ScriptHosts.Contains(name))
        {
            notes.Add($"Uses script host {name}.");
            target = FindScriptArgument(rest);
            if (rest.Contains("-enc", StringComparison.OrdinalIgnoreCase) || rest.Contains("-e ", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add("Command line contains an encoded PowerShell command.");
            }

            if (rest.Contains("http://", StringComparison.OrdinalIgnoreCase) || rest.Contains("https://", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add("Command line contains a URL.");
            }
        }

        return new ResolvedCommand(exe, target, notes);
    }

    private (string Exe, string Remainder) SplitUnquoted(string cmd, List<string> notes)
    {
        // Unquoted paths with spaces: Windows tries "C:\Program", then "C:\Program Files\App\app.exe", …
        var parts = cmd.Split(' ');
        for (var i = 1; i <= parts.Length; i++)
        {
            var candidate = string.Join(' ', parts.Take(i));
            foreach (var c in new[] { candidate, candidate + ".exe" })
            {
                if (_fileExists(c))
                {
                    if (i > 1)
                    {
                        notes.Add("Unquoted path containing spaces (can be hijacked by planting an earlier path component).");
                    }

                    return (c, string.Join(' ', parts.Skip(i)));
                }
            }
        }

        return (parts[0], string.Join(' ', parts.Skip(1)));
    }

    private string Qualify(string file)
    {
        file = file.Trim().Trim('"');
        if (Path.IsPathFullyQualified(file) || file.Length == 0)
        {
            return file;
        }

        foreach (var dir in _searchDirs)
        {
            foreach (var c in new[] { Join(dir, file), Join(dir, file + ".exe") })
            {
                if (_fileExists(c))
                {
                    return c;
                }
            }
        }

        return file;
    }

    /// <summary>Joins with the separator style of <paramref name="dir"/> so Windows paths stay Windows paths on any host.</summary>
    private static string Join(string dir, string file) =>
        dir.Contains('\\', StringComparison.Ordinal) ? dir.TrimEnd('\\') + "\\" + file : Path.Combine(dir, file);

    private string? FindScriptArgument(string rest)
    {
        foreach (var token in Tokenize(rest))
        {
            if (ScriptExtensions.Any(e => token.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
            {
                return Qualify(token);
            }
        }

        return null;
    }

    private static string? FirstArgument(string rest) => Tokenize(rest).FirstOrDefault(t => !t.StartsWith('/') && !t.StartsWith('-'));

    internal static IEnumerable<string> Tokenize(string s)
    {
        var i = 0;
        while (i < s.Length)
        {
            while (i < s.Length && s[i] == ' ')
            {
                i++;
            }

            if (i >= s.Length)
            {
                yield break;
            }

            if (s[i] == '"')
            {
                var end = s.IndexOf('"', i + 1);
                end = end < 0 ? s.Length : end;
                yield return s[(i + 1)..end];
                i = end + 1;
            }
            else
            {
                var end = s.IndexOf(' ', i);
                end = end < 0 ? s.Length : end;
                yield return s[i..end];
                i = end;
            }
        }
    }

    private static string[] DefaultSearchDirs()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var sys = Environment.SystemDirectory;
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return [sys, win, Path.Combine(win, "SysWOW64")];
    }
}
