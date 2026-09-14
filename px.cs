using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess, int pic, byte[] pi, int piLen, out int retLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, int size, out int bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CommandLineToArgvW(string cmdLine, out int numArgs);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    static byte[] SubArray(byte[] src, int offset, int len)
    {
        byte[] r = new byte[len];
        Array.Copy(src, offset, r, 0, len);
        return r;
    }

    // --- True-color (24-bit RGB) support, borrowed from the cycodca Engine/AnsiColor.cs +
    // Highlighter.cs pattern (Atom One Dark palette). Falls back to the nearest 16-color
    // ConsoleColor on terminals that don't advertise true-color support, and skips coloring
    // entirely when output is redirected either way.

    readonly struct AnsiColor
    {
        public readonly byte R, G, B;
        public AnsiColor(int r, int g, int b) { R = (byte)r; G = (byte)g; B = (byte)b; }

        public string FgEscape() => $"\x1b[38;2;{R};{G};{B}m";
        public const string Reset = "\x1b[0m";

        public ConsoleColor ToConsoleColor()
        {
            var best = ConsoleColor.Gray;
            var bestDist = double.MaxValue;
            foreach (var (cc, cr, cg, cb) in _vgaPalette)
            {
                double dr = R - cr, dg = G - cg, db = B - cb;
                double d = dr * dr + dg * dg + db * db;
                if (d < bestDist) { bestDist = d; best = cc; }
            }
            return best;
        }

        static readonly (ConsoleColor CC, byte R, byte G, byte B)[] _vgaPalette =
        {
            (ConsoleColor.Black, 0, 0, 0),
            (ConsoleColor.DarkBlue, 0, 0, 128),
            (ConsoleColor.DarkGreen, 0, 128, 0),
            (ConsoleColor.DarkCyan, 0, 128, 128),
            (ConsoleColor.DarkRed, 128, 0, 0),
            (ConsoleColor.DarkMagenta, 128, 0, 128),
            (ConsoleColor.DarkYellow, 128, 128, 0),
            (ConsoleColor.Gray, 192, 192, 192),
            (ConsoleColor.DarkGray, 128, 128, 128),
            (ConsoleColor.Blue, 0, 0, 255),
            (ConsoleColor.Green, 0, 255, 0),
            (ConsoleColor.Cyan, 0, 255, 255),
            (ConsoleColor.Red, 255, 0, 0),
            (ConsoleColor.Magenta, 255, 0, 255),
            (ConsoleColor.Yellow, 255, 255, 0),
            (ConsoleColor.White, 255, 255, 255),
        };
    }

    static readonly bool SupportsTrueColor = DetectTrueColor();

    static bool DetectTrueColor()
    {
        var colorterm = Environment.GetEnvironmentVariable("COLORTERM");
        if (colorterm is "truecolor" or "24bit") return true;
        if (Environment.GetEnvironmentVariable("WT_SESSION") != null) return true;
        var termProg = Environment.GetEnvironmentVariable("TERM_PROGRAM");
        if (termProg is "iTerm.app" or "Hyper" or "vscode") return true;
        return false;
    }

    static void Write(string text, AnsiColor? color = null)
    {
        if (color == null || Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }

        if (SupportsTrueColor)
        {
            Console.Write(color.Value.FgEscape());
            Console.Write(text);
            Console.Write(AnsiColor.Reset);
        }
        else
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = color.Value.ToConsoleColor();
            Console.Write(text);
            Console.ForegroundColor = prev;
        }
    }

    static void WriteLine(string text = "", AnsiColor? color = null)
    {
        Write(text, color);
        Console.WriteLine();
    }

    // Atom One Dark palette (https://github.com/atom/one-dark-syntax), reused here to give each
    // kind of token (PID, path, option name/value, env name/value, ...) a distinct, semantically
    // meaningful color instead of the flat 16-color palette.
    static class Colors
    {
        public static readonly AnsiColor Header = new(0x61, 0xAF, 0xEF);      // function (blue)
        public static readonly AnsiColor Muted = new(0x5C, 0x63, 0x70);       // comment (muted blue-gray) - parens, path dir/ext
        public static readonly AnsiColor Pid = new(0x98, 0xC3, 0x79);         // string (green)
        public static readonly AnsiColor Name = new(0x61, 0xAF, 0xEF);        // function (blue) - process base name
        public static readonly AnsiColor Subcommand = new(0xC6, 0x78, 0xDD); // keyword (purple) - first bare arg after exe
        public static readonly AnsiColor OptName = new(0x61, 0xAF, 0xEF);     // function (blue) - option prefix + name
        public static readonly AnsiColor OptValue = new(0xD1, 0x9A, 0x66);    // number/constant (orange) - option value
        public static readonly AnsiColor QuotedString = new(0x98, 0xC3, 0x79); // string (green) - quoted args/values
        public static readonly AnsiColor Positional = new(0xAB, 0xB2, 0xBF); // variable (light gray) - bare non-subcommand args
        public static readonly AnsiColor EnvName = new(0xE0, 0x6C, 0x75);     // attribute (red)
        public static readonly AnsiColor EnvValue = new(0xAB, 0xB2, 0xBF);    // variable (light gray)
        public static readonly AnsiColor Error = new(0xE0, 0x6C, 0x75);       // attribute/red
    }

    class ProcessDetails
    {
        public string EnvBlock = "";
        public string ImagePath = "";
        public string CommandLine = "";
        public string Error = ""; // empty = no error
    }

    // Reads a remote UNICODE_STRING given the local copy of its containing struct (ppBuf) and
    // the byte offset within it where the UNICODE_STRING (Length:2, MaximumLength:2, pad:4, Buffer:8) starts.
    static string ReadRemoteUnicodeString(IntPtr h, byte[] ppBuf, int offset)
    {
        ushort length = BitConverter.ToUInt16(ppBuf, offset);
        if (length == 0) return "";

        long bufAddr = BitConverter.ToInt64(ppBuf, offset + 8);
        if (bufAddr == 0) return "";

        byte[] buf = new byte[length];
        int read;
        if (!ReadProcessMemory(h, new IntPtr(bufAddr), buf, length, out read) || read <= 0) return "";

        return Encoding.Unicode.GetString(buf, 0, read);
    }

    static ProcessDetails GetProcessDetails(int pid)
    {
        var details = new ProcessDetails();

        IntPtr h = OpenProcess(0x0410, false, pid); // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            details.Error = "ERROR: OpenProcess failed, code=" + err;
            return details;
        }
        try
        {
            byte[] pbi = new byte[48];
            int retLen;
            int status = NtQueryInformationProcess(h, 0, pbi, pbi.Length, out retLen);
            if (status != 0)
            {
                details.Error = "ERROR: NtQueryInformationProcess status=" + status;
                return details;
            }

            IntPtr pebAddr = new IntPtr(BitConverter.ToInt64(pbi, 8));

            byte[] pebBuf = new byte[0x150];
            int read;
            if (!ReadProcessMemory(h, pebAddr, pebBuf, pebBuf.Length, out read))
            {
                details.Error = "ERROR: ReadProcessMemory(PEB) failed, code=" + Marshal.GetLastWin32Error();
                return details;
            }

            IntPtr procParamsAddr = new IntPtr(BitConverter.ToInt64(pebBuf, 0x20));

            byte[] ppBuf = new byte[0x100];
            if (!ReadProcessMemory(h, procParamsAddr, ppBuf, ppBuf.Length, out read))
            {
                details.Error = "ERROR: ReadProcessMemory(ProcParams) failed, code=" + Marshal.GetLastWin32Error();
                return details;
            }

            // RTL_USER_PROCESS_PARAMETERS (64-bit): ImagePathName UNICODE_STRING at 0x60, CommandLine at 0x70.
            details.ImagePath = ReadRemoteUnicodeString(h, ppBuf, 0x60);
            details.CommandLine = ReadRemoteUnicodeString(h, ppBuf, 0x70);

            IntPtr envAddr = new IntPtr(BitConverter.ToInt64(ppBuf, 0x80));

            int chunkSize = 4096;
            byte[] all = new byte[0];
            int totalRead = 0;
            int maxTotal = 1024 * 1024;
            bool foundEnd = false;
            while (!foundEnd && totalRead < maxTotal)
            {
                byte[] chunk = new byte[chunkSize];
                bool ok = ReadProcessMemory(h, new IntPtr(envAddr.ToInt64() + totalRead), chunk, chunkSize, out read);
                if (!ok || read == 0) break;
                byte[] newAll = new byte[all.Length + read];
                Array.Copy(all, newAll, all.Length);
                Array.Copy(chunk, 0, newAll, all.Length, read);
                all = newAll;
                totalRead += read;
                for (int i = 0; i + 3 < all.Length; i += 2)
                {
                    if (all[i] == 0 && all[i + 1] == 0 && all[i + 2] == 0 && all[i + 3] == 0)
                    {
                        foundEnd = true;
                        all = SubArray(all, 0, i + 2);
                        break;
                    }
                }
            }

            details.EnvBlock = Encoding.Unicode.GetString(all);
            return details;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    // Parses a raw Win32 command-line string into argv, using the same rules the OS itself uses.
    static string[] ParseCommandLine(string cmdLine)
    {
        if (string.IsNullOrEmpty(cmdLine)) return Array.Empty<string>();

        int argc;
        IntPtr argv = CommandLineToArgvW(cmdLine, out argc);
        if (argv == IntPtr.Zero) return Array.Empty<string>();

        try
        {
            var result = new string[argc];
            for (int i = 0; i < argc; i++)
            {
                IntPtr strPtr = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                result[i] = Marshal.PtrToStringUni(strPtr) ?? "";
            }
            return result;
        }
        finally
        {
            LocalFree(argv);
        }
    }

    // Escapes a single argument per the standard Windows CommandLineToArgvW-compatible rules:
    // backslashes are only special immediately before a '"', and must be doubled there (plus one
    // more to escape the quote itself); a run of backslashes at the very end of the argument
    // (right before the closing quote we add) must also be doubled.
    static string EscapeArgumentForWindows(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            return arg;

        var sb = new StringBuilder();
        sb.Append('"');

        for (int i = 0; i < arg.Length; )
        {
            int backslashes = 0;
            while (i < arg.Length && arg[i] == '\\')
            {
                backslashes++;
                i++;
            }

            if (i == arg.Length)
            {
                sb.Append('\\', backslashes * 2);
                break;
            }
            else if (arg[i] == '"')
            {
                sb.Append('\\', backslashes * 2 + 1);
                sb.Append('"');
                i++;
            }
            else
            {
                sb.Append('\\', backslashes);
                sb.Append(arg[i]);
                i++;
            }
        }

        sb.Append('"');
        return sb.ToString();
    }


    static readonly string[] FilterFlags = new[]
    {
        "--contains", "--env-contains", "--name-contains", "--env-name-contains", "--name-starts-with", "--env-name-starts-with",
        "--value-contains", "--env-value-contains", "--value-starts-with", "--env-value-starts-with"
    };

    static readonly string[] BooleanFlags = new[] { "--where", "--args", "--env", "--pid" };

    static void PrintUsage()
    {
        WriteLine("px - inspect running processes: list PIDs, exe paths, command lines, and env vars", Colors.Header);
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  px <pid|process-name|name-fragment> [...] [<filter-value> ...] [<filter-flag> <value> [<value> ...]] ...");
        Console.WriteLine();
        Console.WriteLine("HOW PROCESS TARGETS ARE RESOLVED (in order):");
        Console.WriteLine("  1. Numeric token           -> treated as a PID");
        Console.WriteLine("  2. Exact process name match -> that process (case-insensitive)");
        Console.WriteLine("  3. Token has '*' or '?'     -> glob match against process names (e.g. 'cyco*')");
        Console.WriteLine("  4. If NOTHING matched yet   -> try remaining tokens as name substrings (e.g. 'chrome')");
        Console.WriteLine();
        Console.WriteLine("HOW LEFTOVER TOKENS BECOME ENV-VAR FILTERS:");
        Console.WriteLine("  Once at least one process target is resolved, any leftover token filters env vars");
        Console.WriteLine("  by NAME, in this order:");
        Console.WriteLine("    1. Token has '*' or '?'        -> glob match against variable names");
        Console.WriteLine("    2. Exact match (case-sensitive) -> used if one exists");
        Console.WriteLine("    3. Exact match (case-insensitive) -> used only if no case-sensitive match exists");
        Console.WriteLine("    (no substring/prefix guessing otherwise)");
        Console.WriteLine();
        Console.WriteLine("OTHER FLAGS:");
        Console.WriteLine("  --pid     always show (PID) on the main line, even with --where/--args");
        Console.WriteLine("  --where   show the full path to each process's executable");
        Console.WriteLine("  --args    show the process's command-line args (fancy-colored) on the main line");
        Console.WriteLine("  --env     after everything else, show ALL environment variables for each process");
        Console.WriteLine();
        Console.WriteLine("  By default (neither --where nor --args) the main line is '(PID)  name.exe'.");
        Console.WriteLine("  --where alone shows the full path instead of the PID/name. --args alone shows");
        Console.WriteLine("  'name.exe <args>' instead of the PID. Add --pid to force the PID to show either way.");
        Console.WriteLine("  If BOTH --where and --args are given, the main line is 'name.exe <args>' and the full");
        Console.WriteLine("  path is shown on its own indented line underneath.");
        Console.WriteLine();
        Console.WriteLine("ENV FILTER FLAGS (each implies --env; accepts one or more values, OR'd together):");
        Console.WriteLine("  --env-contains <value> [<value> ...]          (matches if NAME or VALUE contains it)");
        Console.WriteLine("  --env-name-contains <value> [<value> ...]");
        Console.WriteLine("  --env-name-starts-with <value> [<value> ...]");
        Console.WriteLine("  --env-value-contains <value> [<value> ...]");
        Console.WriteLine("  --env-value-starts-with <value> [<value> ...]");
        Console.WriteLine();
        Console.WriteLine("  Shorter aliases (--contains, --name-contains, --name-starts-with, --value-contains,");
        Console.WriteLine("  --value-starts-with) are also accepted for all of the above.");
        Console.WriteLine();
        Console.WriteLine("  A leftover positional token (not resolved to a process) also implies --env and acts");
        Console.WriteLine("  as an env-var NAME filter (see below).");
        Console.WriteLine();
        Console.WriteLine("EXAMPLE:");
        Console.WriteLine("  px 12345");
        Console.WriteLine("  px 12345 67890");
        Console.WriteLine("  px chrome");
        Console.WriteLine("  px chrome notepad");
        Console.WriteLine("  px 'cyco*' --where");
        Console.WriteLine("  px 'cyco*' --args");
        Console.WriteLine("  px 'cyco*' --where --args");
        Console.WriteLine("  px cycodd --env");
        Console.WriteLine("  px cycodd CYCODD_DAEMON_CHILD    (implicit exact-match env var name filter, implies --env)");
        Console.WriteLine("  px cycodd 'CYCODD_*'             (implicit glob env var name filter, implies --env)");
        Console.WriteLine("  px cycodd --env-name-contains PATH TEMP");
        Console.WriteLine("  px cycodd --env-value-contains localhost");
        Console.WriteLine("  px cycodd --env-contains BLH     (matches if var NAME or VALUE contains 'BLH')");
    }

    static string GetProcessNameSafe(int pid)
    {
        try
        {
            return Process.GetProcessById(pid).ProcessName;
        }
        catch
        {
            return "?";
        }
    }

    class ParsedArgs
    {
        public SortedSet<int> Pids = new SortedSet<int>();
        public List<string> Contains = new List<string>();
        public List<string> NameContains = new List<string>();
        public List<string> NameStartsWith = new List<string>();
        public List<string> ValueContains = new List<string>();
        public List<string> ValueStartsWith = new List<string>();
        public bool ShowWhere = false;
        public bool ShowArgs = false;
        public bool ShowEnvExplicit = false;
        public bool ShowPidExplicit = false;

        // Leftover tokens (not resolved to a process): matched against env var NAMES using
        // an exact-first progression (see CompileImplicitFilters), NOT contains/starts-with,
        // unless the token itself contains '*'/'?'.
        public List<string> ImplicitFilters = new List<string>();
        public List<string> UnresolvedTargets = new List<string>();

        public bool HasFilters =>
            Contains.Count > 0 ||
            NameContains.Count > 0 || NameStartsWith.Count > 0 ||
            ValueContains.Count > 0 || ValueStartsWith.Count > 0 ||
            ImplicitFilters.Count > 0;

        // Env vars are shown if --env was given explicitly, OR any env filter (implicit or
        // explicit --env-*) was given - filters imply you want to see the (filtered) env vars.
        public bool ShouldShowEnv => ShowEnvExplicit || HasFilters;

        // When --env is given with NO filters at all, show everything (unfiltered).
        public bool ShowEnvAll => ShowEnvExplicit && !HasFilters;
    }

    static Regex GlobToRegex(string glob)
    {
        var sb = new StringBuilder("^");
        foreach (var c in glob)
        {
            if (c == '*') sb.Append(".*");
            else if (c == '?') sb.Append('.');
            else sb.Append(Regex.Escape(c.ToString()));
        }
        sb.Append('$');
        return new Regex(sb.ToString(), RegexOptions.IgnoreCase);
    }

    static ParsedArgs ParseArgs(string[] args)
    {
        var result = new ParsedArgs();
        var allProcesses = Process.GetProcesses();
        var pending = new List<string>();

        // Pass 1: handle filter flags, numeric PIDs, and exact process-name matches
        // immediately (these are unambiguous). Anything else is deferred to "pending".
        int i = 0;
        while (i < args.Length)
        {
            var arg = args[i];

            var argLower = arg.ToLowerInvariant();

            if (argLower == "--where")
            {
                result.ShowWhere = true;
                i++;
                continue;
            }

            if (argLower == "--args")
            {
                result.ShowArgs = true;
                i++;
                continue;
            }

            if (argLower == "--env")
            {
                result.ShowEnvExplicit = true;
                i++;
                continue;
            }

            if (argLower == "--pid")
            {
                result.ShowPidExplicit = true;
                i++;
                continue;
            }

            if (Array.IndexOf(FilterFlags, argLower) >= 0)
            {
                var target = arg.ToLowerInvariant() switch
                {
                    "--contains" or "--env-contains" => result.Contains,
                    "--name-contains" or "--env-name-contains" => result.NameContains,
                    "--name-starts-with" or "--env-name-starts-with" => result.NameStartsWith,
                    "--value-contains" or "--env-value-contains" => result.ValueContains,
                    "--value-starts-with" or "--env-value-starts-with" => result.ValueStartsWith,
                    _ => null
                };
                i++;
                while (i < args.Length &&
                       Array.IndexOf(FilterFlags, args[i].ToLowerInvariant()) < 0 &&
                       Array.IndexOf(BooleanFlags, args[i].ToLowerInvariant()) < 0)
                {
                    target!.Add(args[i]);
                    i++;
                }
                continue;
            }

            int pid;
            if (int.TryParse(arg, out pid))
            {
                result.Pids.Add(pid);
                i++;
                continue;
            }

            if (arg.IndexOf('*') >= 0 || arg.IndexOf('?') >= 0)
            {
                // Explicit wildcard: try it as a process-name glob first (unconditionally,
                // regardless of whether other exact matches already exist). If it matches
                // zero processes, don't discard it - let it fall through to "pending" so it
                // can still be used as an env-var-name glob filter (e.g. 'CYCODD_*').
                var regex = GlobToRegex(arg);
                var globMatches = allProcesses.Where(p => regex.IsMatch(p.ProcessName)).ToArray();
                if (globMatches.Length > 0)
                {
                    foreach (var p in globMatches) result.Pids.Add(p.Id);
                    i++;
                    continue;
                }

                pending.Add(arg);
                i++;
                continue;
            }

            var exactMatches = allProcesses.Where(p => string.Equals(p.ProcessName, arg, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (exactMatches.Length > 0)
            {
                foreach (var p in exactMatches) result.Pids.Add(p.Id);
                i++;
                continue;
            }

            pending.Add(arg);
            i++;
        }

        // Pass 2: if we already have definite targets (from PIDs or exact name matches),
        // any remaining "pending" tokens are unambiguously filters - no fragment stealing.
        // Only if we have NO definite targets yet do we fall back to fragment/substring
        // matching against process names, so a lone token like "chrome" still works.
        if (result.Pids.Count == 0)
        {
            var stillPending = new List<string>();
            foreach (var arg in pending)
            {
                var substringMatches = allProcesses.Where(p => p.ProcessName.IndexOf(arg, StringComparison.OrdinalIgnoreCase) >= 0).ToArray();
                if (substringMatches.Length > 0)
                    foreach (var p in substringMatches) result.Pids.Add(p.Id);
                else
                    stillPending.Add(arg);
            }
            pending = stillPending;
        }

        foreach (var arg in pending)
        {
            result.ImplicitFilters.Add(arg);
            result.UnresolvedTargets.Add(arg);
        }

        return result;
    }

    // For each implicit (leftover) filter token, decide its match strategy against the
    // ACTUAL variable names of one specific process:
    //   1. Token has '*' or '?'  -> glob match (case-insensitive), can match multiple names.
    //   2. Else, if some var name equals the token exactly (case-sensitive)  -> use that,
    //      i.e. do NOT fall back to case-insensitive matching.
    //   3. Else, if some var name equals the token exactly (case-insensitive) -> use that.
    //   4. Else -> token matches nothing for this process (no contains/starts-with fallback).
    static List<Func<string, bool>> CompileImplicitFilters(List<string> tokens, string[] varNames)
    {
        var predicates = new List<Func<string, bool>>();
        foreach (var token in tokens)
        {
            if (token.IndexOf('*') >= 0 || token.IndexOf('?') >= 0)
            {
                var regex = GlobToRegex(token);
                predicates.Add(name => regex.IsMatch(name));
                continue;
            }

            var t = token;
            if (varNames.Any(n => string.Equals(n, t, StringComparison.Ordinal)))
            {
                predicates.Add(name => string.Equals(name, t, StringComparison.Ordinal));
                continue;
            }

            if (varNames.Any(n => string.Equals(n, t, StringComparison.OrdinalIgnoreCase)))
            {
                predicates.Add(name => string.Equals(name, t, StringComparison.OrdinalIgnoreCase));
                continue;
            }

            predicates.Add(name => false);
        }
        return predicates;
    }

    static bool PassesFilters(ParsedArgs parsed, string name, string value, List<Func<string, bool>> compiledImplicit)
    {
        if (!parsed.HasFilters)
            return true;

        if (parsed.Contains.Any(f => name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.NameContains.Any(f => name.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.NameStartsWith.Any(f => name.StartsWith(f, StringComparison.OrdinalIgnoreCase))) return true;
        if (parsed.ValueContains.Any(f => value.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)) return true;
        if (parsed.ValueStartsWith.Any(f => value.StartsWith(f, StringComparison.OrdinalIgnoreCase))) return true;
        if (compiledImplicit.Any(p => p(name))) return true;

        return false;
    }

    // Writes a filesystem path with the directory portion and file extension muted, and just
    // the filename's base (no dir, no extension) in the "Name" color -
    // e.g. C:\dir\ (muted) cycod (blue) .exe (muted).
    static void WriteExePathColored(string display)
    {
        int lastSlash = display.LastIndexOfAny(new[] { '\\', '/' });
        string dirPart = lastSlash >= 0 ? display.Substring(0, lastSlash + 1) : "";
        string fileName = lastSlash >= 0 ? display.Substring(lastSlash + 1) : display;

        int lastDot = fileName.LastIndexOf('.');
        string baseName = lastDot > 0 ? fileName.Substring(0, lastDot) : fileName;
        string ext = lastDot > 0 ? fileName.Substring(lastDot) : "";

        Write(dirPart, Colors.Muted);
        Write(baseName, Colors.Name);
        Write(ext, Colors.Muted);
    }

    // Writes a single already-escaped command-line argument with "fancy" One-Dark-inspired
    // coloring:
    //   - quoted args (start with '"')                -> whole token in QuotedString (green)
    //   - option-looking args (--, -, or / prefix)      -> prefix+name in OptName (blue),
    //                                                       value after '='/':' in OptValue
    //                                                       (orange), or QuotedString if the
    //                                                       value itself is quoted
    //   - the FIRST bare/positional arg after the exe   -> Subcommand (purple), as if it were
    //                                                       a declaration/verb
    //   - any later bare/positional arg                 -> Positional (light gray)
    static void WriteArgColored(string arg, ref bool isFirstPositional)
    {
        if (arg.StartsWith("\""))
        {
            Write(arg, Colors.QuotedString);
            return;
        }

        string optPrefix =
            arg.StartsWith("--") ? "--" :
            arg.StartsWith("/") ? "/" :
            arg.StartsWith("-") ? "-" :
            "";

        if (optPrefix == "")
        {
            Write(arg, isFirstPositional ? Colors.Subcommand : Colors.Positional);
            isFirstPositional = false;
            return;
        }

        int splitAt = arg.IndexOfAny(new[] { '=', ':' });
        string namePart = splitAt >= 0 ? arg.Substring(0, splitAt) : arg;
        string valuePart = splitAt >= 0 ? arg.Substring(splitAt) : "";

        Write(namePart, Colors.OptName);
        if (valuePart.Length > 0)
        {
            var sep = valuePart[0];
            var valueRest = valuePart.Substring(1);
            Write(sep.ToString(), Colors.Muted);
            Write(valueRest, valueRest.StartsWith("\"") ? Colors.QuotedString : Colors.OptValue);
        }
    }

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return;
        }

        var parsed = ParseArgs(args);

        if (parsed.Pids.Count == 0)
        {
            WriteLine("ERROR: no PID and no running process matched any of the given names/fragments '" + string.Join("', '", parsed.UnresolvedTargets) + "'", Colors.Error);
            return;
        }

        var detailsByPid = new Dictionary<int, ProcessDetails>();
        foreach (var pid in parsed.Pids)
            detailsByPid[pid] = GetProcessDetails(pid);

        bool showPid = parsed.ShowPidExplicit || (!parsed.ShowWhere && !parsed.ShowArgs);
        bool showLocationIndented = parsed.ShowWhere && parsed.ShowArgs;

        var entries = parsed.Pids
            .Select(pid =>
            {
                var details = detailsByPid[pid];
                var shortName = GetProcessNameSafe(pid) + ".exe";
                var argv = ParseCommandLine(details.CommandLine);
                var restArgs = argv.Length > 1 ? argv.Skip(1).Select(EscapeArgumentForWindows).ToArray() : Array.Empty<string>();

                // Sort key matches what's actually relevant/visible: by full path only when
                // --where is in effect, otherwise by the short name (even if --args is also
                // shown, since the args themselves aren't a stable sort key).
                var sortKey = parsed.ShowWhere && !string.IsNullOrEmpty(details.ImagePath) ? details.ImagePath : shortName;

                return (Pid: pid, Details: details, ShortName: shortName, RestArgs: restArgs, SortKey: sortKey);
            })
            .OrderBy(e => e.SortKey, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        int pidDigits = entries.Length == 0 ? 0 : entries.Max(e => e.Pid.ToString().Length);

        foreach (var e in entries)
        {
            if (showPid)
            {
                var pidDigitsStr = e.Pid.ToString().PadLeft(pidDigits);
                Write("(", Colors.Muted);
                Write(pidDigitsStr, Colors.Pid);
                Write(")", Colors.Muted);
                Write("  ");
            }

            // --- Main line content ---
            if (parsed.ShowArgs)
            {
                Write(e.ShortName, Colors.Name);
                bool isFirstPositional = true;
                foreach (var a in e.RestArgs)
                {
                    Write(" ");
                    WriteArgColored(a, ref isFirstPositional);
                }
            }
            else if (parsed.ShowWhere && !string.IsNullOrEmpty(e.Details.ImagePath))
            {
                WriteExePathColored(e.Details.ImagePath);
            }
            else
            {
                WriteExePathColored(e.ShortName);
            }

            Console.WriteLine();

            // --- Indented location line, only when both --args and --where are given ---
            if (showLocationIndented && !string.IsNullOrEmpty(e.Details.ImagePath))
            {
                Console.WriteLine();
                WriteLine("  " + e.Details.ImagePath, Colors.Muted);
                Console.WriteLine();
            }

            // --- Env vars, only if explicitly requested or filtered ---
            if (!parsed.ShouldShowEnv) continue;

            if (!showLocationIndented) Console.WriteLine();

            if (!string.IsNullOrEmpty(e.Details.Error))
            {
                WriteLine("  " + e.Details.Error, Colors.Error);
                Console.WriteLine();
                continue;
            }

            var vars = e.Details.EnvBlock.Split('\0').Where(v => !string.IsNullOrEmpty(v)).ToArray();
            Array.Sort(vars, StringComparer.OrdinalIgnoreCase);

            var parsedVars = vars.Select(v =>
            {
                var eq = v.IndexOf('=', v.StartsWith("=") ? 1 : 0);
                var name = eq >= 0 ? v.Substring(0, eq) : v;
                var value = eq >= 0 ? v.Substring(eq + 1) : "";
                return (Raw: v, Name: name, Value: value);
            }).ToArray();

            var varNames = parsedVars.Select(pv => pv.Name).ToArray();
            var compiledImplicit = CompileImplicitFilters(parsed.ImplicitFilters, varNames);

            int matchCount = 0;
            foreach (var pv in parsedVars)
            {
                if (parsed.ShowEnvAll || PassesFilters(parsed, pv.Name, pv.Value, compiledImplicit))
                {
                    matchCount++;
                    Write("  ");
                    Write(pv.Name, Colors.EnvName);
                    Write("=");
                    WriteLine(pv.Value, Colors.EnvValue);
                }
            }

            if (matchCount == 0)
                WriteLine("  (no matching environment variables)", Colors.Muted);

            Console.WriteLine();
        }
    }
}
