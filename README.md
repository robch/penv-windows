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
- .NET 10 SDK to build
- You must have permission to read the target process's memory (this
  generally works for your own processes without elevation; for processes
  owned by other users you'll need to run elevated)

## Build

```
dotnet build
```

The debug build output is:

```
bin\Debug\net10.0\px.exe
```
