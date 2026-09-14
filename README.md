# px

`px` (formerly `penv`) is a small Windows console utility for inspecting
running processes: resolve them by PID, exact name, name fragment, or glob;
list their PIDs and executable names/paths; dump a ready-to-run command line
(exe + properly re-escaped args); and print/filter their environment
variables.

Windows doesn't expose another process's environment block (or full
command line) through normal tools like `tasklist` or PowerShell's
`Get-Process` - you have to read it directly out of the target process's
memory. `px` does this by:

1. Calling `OpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
2. Calling `NtQueryInformationProcess` to get the process's **PEB** address
3. Reading the PEB to get the `RTL_USER_PROCESS_PARAMETERS` pointer
4. Reading `ProcessParameters` to get the `ImagePathName`, `CommandLine`,
   and `Environment` block pointers
5. Reading each of those and printing/filtering the results

## Requirements

- Windows, x64
- .NET 8 SDK to build
- You must have permission to read the target process's memory (this
  generally works for your own processes without elevation; for processes
  owned by other users you'll need to run elevated)

## Build

```
dotnet build
```

The debug build output is:

```
bin\Debug\net8.0\px.exe
```

## Usage

```
px <pid|process-name|name-fragment> [...] [<filter-value> ...] [<filter-flag> <value> [<value> ...]] ...
```

Run `px` with no arguments to see the full built-in help, including:

- **How process targets are resolved**: numeric PID, exact process name
  match, `*`/`?` glob against process names, or (as a last resort, only if
  nothing else matched) a plain substring/fragment match.
- **How leftover tokens become env-var filters**: once at least one process
  target is resolved, any leftover token filters environment variables by
  name (exact match preferred, case-sensitive first; glob via `*`/`?`; no
  accidental substring/prefix guessing).
- **`--where`**: show the full path to each process's executable.
- **`--args`**: show a runnable `exe + args` command line per process,
  properly escaped per Windows argv-quoting rules.
- **`--env`** and the **`--env-contains`/`--env-name-contains`/
  `--env-name-starts-with`/`--env-value-contains`/`--env-value-starts-with`**
  flags for showing/filtering environment variables.

### Examples

```
> px cycod
(60392)  cycod.exe

> px "cyco*" --where
(59308)  c:\src\...\cycodd.exe
(59804)  c:\src\...\cycodd.exe
...

> px "cyco*" --args
(60392)  cycod.exe
...

=== ARGS (executable + args) ===
cycod.exe --revive
...

> px cycod --env
(60392)  cycod.exe

=== ENVIRONMENT VARIABLES ===

--- PID 60392 (cycod) ---
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\r\AppData\Roaming
...
```

## Adding to your PATH automatically

If you keep a `c:\util\autorun.cmd` that runs at shell startup (e.g. via
Clink or similar), you can add a snippet like this so `px` is
automatically available whenever this repo is built:

```bat
if exist C:\src\penv-windows\bin\Debug\net8.0\px.exe call :addpath "C:\src\penv-windows\bin\Debug\net8.0"
```
