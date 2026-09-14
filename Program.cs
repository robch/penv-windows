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
        "--contains", "--name-contains", "--name-starts-with", "--value-contains", "--value-starts-with"
    };

    static readonly string[] BooleanFlags = new[] { "--where", "--args" };

    static void PrintUsage()
    {
        Console.WriteLine("penv - print environment variables of a running process by PID or name fragment");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  penv <pid|process-name|name-fragment> [...] [<filter-value> ...] [<filter-flag> <value> [<value> ...]] ...");
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
        Console.WriteLine("FILTER FLAGS (each accepts one or more values, OR'd together with all other filters):");
        Console.WriteLine("  --contains <value> [<value> ...]          (matches if NAME or VALUE contains it)");
        Console.WriteLine("  --name-contains <value> [<value> ...]");
        Console.WriteLine("  --name-starts-with <value> [<value> ...]");
        Console.WriteLine("  --value-contains <value> [<value> ...]");
        Console.WriteLine("  --value-starts-with <value> [<value> ...]");
        Console.WriteLine();
        Console.WriteLine("OTHER FLAGS:");
        Console.WriteLine("  --where   after normal output, also list the full path to each process's exe");
        Console.WriteLine("  --args    after normal output, also list a runnable exe+args command line per process");
        Console.WriteLine();
        Console.WriteLine("EXAMPLE:");
        Console.WriteLine("  penv 12345");
        Console.WriteLine("  penv 12345 67890");
        Console.WriteLine("  penv chrome");
        Console.WriteLine("  penv chrome notepad");
        Console.WriteLine("  penv cycodd CYCODD_DAEMON_CHILD (implicit exact-match env var name filter)");
        Console.WriteLine("  penv cycodd 'CYCODD_*'          (implicit glob env var name filter)");
        Console.WriteLine("  penv cycodd --name-contains PATH TEMP");
        Console.WriteLine("  penv cycodd --value-contains localhost");
        Console.WriteLine("  penv cycodd --contains BLH      (matches if var NAME or VALUE contains 'BLH')");
        Console.WriteLine("  penv 'cyco*' --where");
        Console.WriteLine("  penv 'cyco*' --args");
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

            if (Array.IndexOf(FilterFlags, argLower) >= 0)
            {
                var target = arg.ToLowerInvariant() switch
                {
                    "--contains" => result.Contains,
                    "--name-contains" => result.NameContains,
                    "--name-starts-with" => result.NameStartsWith,
                    "--value-contains" => result.ValueContains,
                    "--value-starts-with" => result.ValueStartsWith,
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
            Console.WriteLine("ERROR: no PID and no running process matched any of the given names/fragments '" + string.Join("', '", parsed.UnresolvedTargets) + "'");
            return;
        }

        var detailsByPid = new Dictionary<int, ProcessDetails>();

        foreach (var pid in parsed.Pids)
        {
            Console.WriteLine("=== PID " + pid + " (" + GetProcessNameSafe(pid) + ") ===");
            var details = GetProcessDetails(pid);
            detailsByPid[pid] = details;

            if (!string.IsNullOrEmpty(details.Error))
            {
                Console.WriteLine(details.Error);
            }
            else
            {
                var vars = details.EnvBlock.Split('\0').Where(v => !string.IsNullOrEmpty(v)).ToArray();
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

                foreach (var pv in parsedVars)
                {
                    if (PassesFilters(parsed, pv.Name, pv.Value, compiledImplicit))
                        Console.WriteLine(pv.Raw);
                }
            }
            Console.WriteLine();
        }

        if (parsed.ShowWhere)
        {
            var entries = detailsByPid
                .Where(kv => !string.IsNullOrEmpty(kv.Value.ImagePath))
                .Select(kv => (Pid: kv.Key, Path: kv.Value.ImagePath))
                .OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Console.WriteLine();
            Console.WriteLine("=== WHERE (full path to executable) ===");

            int pidDigits = entries.Length == 0 ? 0 : entries.Max(e => e.Pid.ToString().Length);
            foreach (var e in entries)
            {
                var pidStr = ("(" + e.Pid + ")").PadRight(pidDigits + 2);
                Console.WriteLine(pidStr + "  " + e.Path);
            }
        }

        if (parsed.ShowArgs)
        {
            var entries = detailsByPid
                .Where(kv => !string.IsNullOrEmpty(kv.Value.ImagePath))
                .Select(kv =>
                {
                    var argv = ParseCommandLine(kv.Value.CommandLine);
                    var restArgs = argv.Length > 1 ? argv.Skip(1) : Enumerable.Empty<string>();
                    var line = EscapeArgumentForWindows(kv.Value.ImagePath) + string.Concat(restArgs.Select(a => " " + EscapeArgumentForWindows(a)));
                    return (Path: kv.Value.ImagePath, Line: line);
                })
                .OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Console.WriteLine();
            Console.WriteLine("=== ARGS (executable + args, ready to run) ===");

            foreach (var e in entries)
                Console.WriteLine(e.Line);
        }
    }
}
