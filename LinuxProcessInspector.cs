using System;
using System.IO;
using System.Runtime.Versioning;

// Linux exposes everything px needs directly as files under /proc/<pid>/, with no elevation
// needed for your own processes (same-user access to others' is normally allowed too; root
// required only for processes owned by other users) - no memory-reading tricks required:
//
//   /proc/<pid>/environ  - NUL-separated "NAME=VALUE" entries, same format GetProcessDetails
//                          already parses on Windows (ParseEnvironmentBlock in px.cs works as-is)
//   /proc/<pid>/cmdline  - NUL-separated argv, already split by the kernel (no CommandLineToArgvW
//                          equivalent needed - ParseCommandLine becomes a trivial Split('\0'))
//   /proc/<pid>/cwd      - symlink; File.ResolveLinkTarget / readlink gives the current directory
//   /proc/<pid>/exe      - symlink; resolves to the on-disk executable path
//   /proc/<pid>/stat     - whitespace-separated fields; field 4 (1-indexed) is the parent pid
//                          (careful: field 2, the comm name, is parenthesized and may itself
//                          contain spaces/parens, so it can't be split naively - skip past the
//                          last ')' first)
//
// This is intentionally left unimplemented for now - stubbed so the rest of px (arg parsing,
// filtering, --tree, colorized rendering, run/shell/rerun launching) can be verified unbroken
// on Windows first, before wiring up the Linux path.
[SupportedOSPlatform("linux")]
class LinuxProcessInspector : IProcessInspector
{
    public ProcessDetails GetProcessDetails(int pid)
    {
        throw new NotImplementedException("Linux support is not implemented yet - see comments in LinuxProcessInspector.cs for the /proc-based plan.");
    }

    public int GetParentPidOnly(int pid)
    {
        throw new NotImplementedException("Linux support is not implemented yet - see comments in LinuxProcessInspector.cs for the /proc-based plan.");
    }

    // /proc/<pid>/cmdline already gives argv split by NUL - no re-parsing needed, unlike Windows.
    public string[] ParseCommandLine(string cmdLine)
    {
        return string.IsNullOrEmpty(cmdLine)
            ? Array.Empty<string>()
            : cmdLine.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    // POSIX shell-safe quoting: wrap in single quotes, escaping any embedded single quote as
    // '\'' (close quote, escaped literal quote, reopen quote). Simpler and more robust than
    // trying to mirror bash's many special characters individually.
    public string EscapeArgumentForDisplay(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\'', '"', '$', '`', '\\', '!', '*', '?', '[', ']', '(', ')', '{', '}', '&', '|', ';', '<', '>', '~' }) < 0)
            return arg;

        return "'" + arg.Replace("'", "'\\''") + "'";
    }
}
