# penv-windows

`penv` is a small Windows console utility that prints the **environment
variables of another running process**, given its process ID (PID).

Windows doesn't expose another process's environment block through normal
tools like `tasklist` or PowerShell's `Get-Process` — you have to read it
directly out of the target process's memory. `penv` does this by:

1. Calling `OpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
2. Calling `NtQueryInformationProcess` to get the process's **PEB** address
3. Reading the PEB to get the `RTL_USER_PROCESS_PARAMETERS` pointer
4. Reading `ProcessParameters` to get the `Environment` block pointer
5. Reading the environment block (a `\0`-separated, double-`\0`-terminated
   Unicode string of `NAME=VALUE` pairs) and printing it out, sorted

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
bin\Debug\net8.0\penv.exe
```

## Usage

```
penv <pid> [<pid> ...]
```

### Example

```
> penv 41168 43972
=== PID 41168 ===
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\r\AppData\Roaming
...

=== PID 43972 ===
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\r\AppData\Roaming
...
```

## Adding to your PATH automatically

If you keep a `c:\util\autorun.cmd` that runs at shell startup (e.g. via
Clink or similar), you can add a snippet like this so `penv` is
automatically available whenever this repo is built:

```bat
if exist C:\src\penv-windows\bin\Debug\net8.0\penv.exe call :addpath "C:\src\penv-windows\bin\Debug\net8.0"
```
