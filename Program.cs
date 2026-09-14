using System;
using System.Runtime.InteropServices;
using System.Text;

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

    static byte[] SubArray(byte[] src, int offset, int len)
    {
        byte[] r = new byte[len];
        Array.Copy(src, offset, r, 0, len);
        return r;
    }

    static string GetEnv(int pid)
    {
        IntPtr h = OpenProcess(0x0410, false, pid); // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return "ERROR: OpenProcess failed, code=" + err;
        }
        try
        {
            byte[] pbi = new byte[48];
            int retLen;
            int status = NtQueryInformationProcess(h, 0, pbi, pbi.Length, out retLen);
            if (status != 0) return "ERROR: NtQueryInformationProcess status=" + status;

            IntPtr pebAddr = new IntPtr(BitConverter.ToInt64(pbi, 8));

            byte[] pebBuf = new byte[0x150];
            int read;
            if (!ReadProcessMemory(h, pebAddr, pebBuf, pebBuf.Length, out read))
                return "ERROR: ReadProcessMemory(PEB) failed, code=" + Marshal.GetLastWin32Error();

            IntPtr procParamsAddr = new IntPtr(BitConverter.ToInt64(pebBuf, 0x20));

            byte[] ppBuf = new byte[0x100];
            if (!ReadProcessMemory(h, procParamsAddr, ppBuf, ppBuf.Length, out read))
                return "ERROR: ReadProcessMemory(ProcParams) failed, code=" + Marshal.GetLastWin32Error();

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

            return Encoding.Unicode.GetString(all);
        }
        finally
        {
            CloseHandle(h);
        }
    }

    static void PrintUsage()
    {
        Console.WriteLine("penv - print environment variables of a running process by PID");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  penv <pid> [<pid> ...]");
        Console.WriteLine();
        Console.WriteLine("EXAMPLE:");
        Console.WriteLine("  penv 12345");
        Console.WriteLine("  penv 12345 67890");
    }

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return;
        }

        foreach (var arg in args)
        {
            int pid;
            if (!int.TryParse(arg, out pid))
            {
                Console.WriteLine("ERROR: invalid PID '" + arg + "'");
                continue;
            }

            Console.WriteLine("=== PID " + pid + " ===");
            string result = GetEnv(pid);
            if (result.StartsWith("ERROR"))
            {
                Console.WriteLine(result);
            }
            else
            {
                var vars = result.Split('\0');
                Array.Sort(vars, StringComparer.OrdinalIgnoreCase);
                foreach (var v in vars)
                {
                    if (!string.IsNullOrEmpty(v))
                        Console.WriteLine(v);
                }
            }
            Console.WriteLine();
        }
    }
}
