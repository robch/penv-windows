using System;
using System.Runtime.Versioning;

// macOS has no /proc filesystem, so unlike Linux this needs its own native-API layer - similar
// effort-level to the Windows PEB-reading, just against different (semi-)documented APIs:
//
//   Command line + environment: sysctl(CTL_KERN, KERN_PROCARGS2, pid) via P/Invoke into
//                                libSystem/libc - returns argc followed by a NUL-separated
//                                argv+environ blob that has to be walked manually (skip the
//                                leading exec_path, then argc strings, then env strings to
//                                the end of the buffer).
//   Image path:                  proc_pidpath() from libproc.
//   Current working directory:   proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, ...) from libproc,
//                                 reading pvi_cdir.vip_path.
//   Parent pid:                  proc_pidinfo(pid, PROC_PIDTBSDINFO, ...) -> pbi_ppid, also
//                                 from libproc (or kinfo_proc via sysctl KERN_PROC/KERN_PROC_PID).
//
// This is intentionally left unimplemented for now - stubbed so the rest of px (arg parsing,
// filtering, --tree, colorized rendering, run/shell/rerun launching) can be verified unbroken
// on Windows first, before wiring up the macOS path.
[SupportedOSPlatform("macos")]
class MacProcessInspector : IProcessInspector
{
    public ProcessDetails GetProcessDetails(int pid)
    {
        throw new NotImplementedException("macOS support is not implemented yet - see comments in MacProcessInspector.cs for the libproc/sysctl-based plan.");
    }

    public int GetParentPidOnly(int pid)
    {
        throw new NotImplementedException("macOS support is not implemented yet - see comments in MacProcessInspector.cs for the libproc/sysctl-based plan.");
    }

    // KERN_PROCARGS2 already hands back argv as discrete NUL-separated strings - no re-parsing
    // needed, unlike Windows.
    public string[] ParseCommandLine(string cmdLine)
    {
        return string.IsNullOrEmpty(cmdLine)
            ? Array.Empty<string>()
            : cmdLine.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    // Same POSIX shell-safe quoting rule as Linux.
    public string EscapeArgumentForDisplay(string arg)
    {
        if (arg.Length != 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\'', '"', '$', '`', '\\', '!', '*', '?', '[', ']', '(', ')', '{', '}', '&', '|', ';', '<', '>', '~' }) < 0)
            return arg;

        return "'" + arg.Replace("'", "'\\''") + "'";
    }
}
