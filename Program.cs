using Roaba_Matii;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using static Roaba_Matii.AdvancedThreadPoolDetector;


namespace Roaba_Matii
{
    public class Settings
    {
        public static bool isRobloxOffsetEnabled = false;
        public static bool isAlertableOnly = false;
    }

    public class AdvancedThreadPoolDetector
    {
        // ═══════════════════════════════════════════════════════
        // STRUCTURES
        // ═══════════════════════════════════════════════════════

        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_POOL_INFORMATION
        {
            public bool IsPoolThread;  // True if thread is from pool
            public IntPtr PoolId;      // Pool identifier
            public uint Flags;         // Additional flags
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public IntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip;
            // minimal version is enough for Rip/Rsp manipulation
        }

        // ═══════════════════════════════════════════════════════
        // P/INVOKE
        // ═══════════════════════════════════════════════════════

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint GetThreadId(IntPtr hThread);

        // ═══════════════════════════════════════════════════════
        // CONSTANTS
        // ═══════════════════════════════════════════════════════

        const uint TH32CS_SNAPTHREAD = 0x00000004;
        const uint THREAD_ALL_ACCESS = 0x001F03FF;
        const uint CONTEXT_FULL = 0x10000F;

        const int ThreadPoolInformation = 0x26;
        const int ThreadBasicInformation = 0x00;

        // ═══════════════════════════════════════════════════════
        // THREAD POOL DETECTION
        // ═══════════════════════════════════════════════════════

        bool OffsetsEnabled = Settings.isRobloxOffsetEnabled;
        bool AlertableOnly = Settings.isAlertableOnly;
        bool Verbose = true;

        public static List<uint> FindAdvancedThreadPools(
            Process targetProcess,
            bool alertableOnly = false, //change to true if roblox
            bool robloxHeuristics = false, //change to true if roblox
            bool verbose = true
        )
        {
            List<uint> poolThreads = new List<uint>();

            Console.WriteLine("\n╔═══════════════════════════════════════════════════╗");
            Console.WriteLine("║    ADVANCED THREAD POOL DETECTION           ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════╝\n");

            if (verbose)
            {
                Console.WriteLine($"[SCAN] Target Process: {targetProcess.ProcessName} (PID: {targetProcess.Id})");
                Console.WriteLine($"[SCAN] Filters: Alertable={alertableOnly}, RobloxHeuristics={robloxHeuristics}");
                Console.WriteLine($"[SCAN] Scanning system threads...\n");
            }

            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] CreateToolhelp32Snapshot failed!");
                Console.ResetColor();
                return poolThreads;
            }

            THREADENTRY32 te = new THREADENTRY32
            {
                dwSize = (uint)Marshal.SizeOf<THREADENTRY32>()
            };

            if (!Thread32First(snap, ref te))
            {
                Console.WriteLine("[-] Thread32First failed!");
                CloseHandle(snap);
                return poolThreads;
            }

            int totalThreads = 0;
            int processThreads = 0;
            int poolCandidates = 0;

            do
            {
                totalThreads++;

                if (te.th32OwnerProcessID == (uint)targetProcess.Id)
                {
                    processThreads++;

                    IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
                    if (hThread != IntPtr.Zero)
                    {
                        try
                        {
                            // ═══════════════════════════════════════════════════════
                            // CHECK 1: Is it a pool thread? (Kernel-level check)
                            // ═══════════════════════════════════════════════════════

                            IntPtr infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<THREAD_POOL_INFORMATION>());
                            uint retLen;

                            int status = NtQueryInformationThread(
                                hThread,
                                ThreadPoolInformation,
                                infoPtr,
                                (uint)Marshal.SizeOf<THREAD_POOL_INFORMATION>(),
                                out retLen
                            );

                            if (status == 0)
                            {
                                THREAD_POOL_INFORMATION poolInfo = Marshal.PtrToStructure<THREAD_POOL_INFORMATION>(infoPtr);

                                if (poolInfo.IsPoolThread)
                                {
                                    poolCandidates++;

                                    // ═══════════════════════════════════════════════════════
                                    // CHECK 2: Get thread context (RIP, RSP, etc.)
                                    // ═══════════════════════════════════════════════════════

                                    CONTEXT64 ctx = new CONTEXT64
                                    {
                                        ContextFlags = CONTEXT_FULL
                                    };


                                    if (GetThreadContext(hThread, ref ctx))
                                    {
                                    
                                        bool passesFilters = true;

                                        // ═══════════════════════════════════════════════════════
                                        // CHECK 3: Roblox-specific heuristics
                                        // ═══════════════════════════════════════════════════════

                                        if (robloxHeuristics)
                                        {
                                            // Filter 1: Thread ID > 1000 (background pools)
                                            bool validTID = te.th32ThreadID > 1000;

                                            // Filter 2: RIP in valid range (ntdll or Roblox module)
                                            // Typical range: 0x7FF000000000 - 0x800000000000
                                            bool validRIP = ctx.Rip > 0x7FF000000000 && ctx.Rip < 0x800000000000;

                                            // Filter 3: RSP looks like a valid stack
                                            bool validRSP = ctx.Rsp > 0x1000 && ctx.Rsp < 0x7FFFFFFFFFFF;

                                            passesFilters = validTID && validRIP && validRSP;

                                            if (verbose && !passesFilters)
                                            {
                                                Console.ForegroundColor = ConsoleColor.Yellow;
                                                Console.WriteLine($"[FILTER] TID {te.th32ThreadID} failed heuristics:");
                                                if (!validTID) Console.WriteLine($"  - TID too low: {te.th32ThreadID}");
                                                if (!validRIP) Console.WriteLine($"  - RIP out of range: 0x{ctx.Rip:X}");
                                                if (!validRSP) Console.WriteLine($"  - RSP invalid: 0x{ctx.Rsp:X}");
                                                Console.ResetColor();
                                            }
                                        }

                                        // ═══════════════════════════════════════════════════════
                                        // CHECK 4: Alertable wait state (optional)
                                        // ═══════════════════════════════════════════════════════

                                        if (alertableOnly)
                                        {
                                            // Check if thread is in alertable wait
                                            // This is indicated by RIP pointing to wait functions in ntdll
                                            // Common wait functions: NtWaitForSingleObject, NtDelayExecution

                                            bool isWaiting = IsThreadInWaitState(ctx.Rip);
                                            passesFilters = passesFilters && isWaiting;

                                            if (verbose && !isWaiting)
                                            {
                                                Console.ForegroundColor = ConsoleColor.Yellow;
                                                Console.WriteLine($"[FILTER] TID {te.th32ThreadID} not in wait state (RIP: 0x{ctx.Rip:X})");
                                                Console.ResetColor();
                                            }
                                        }

                                        // ═══════════════════════════════════════════════════════
                                        // ACCEPT THREAD IF IT PASSES ALL FILTERS
                                        // ═══════════════════════════════════════════════════════

                                        if (passesFilters)
                                        {
                                            poolThreads.Add(te.th32ThreadID);

                                            if (verbose)
                                            {
                                                Console.ForegroundColor = ConsoleColor.Green;
                                                Console.WriteLine($"[✓] Pool Thread Found:");
                                                Console.WriteLine($"    TID:      {te.th32ThreadID}");
                                                Console.WriteLine($"    RIP:      0x{ctx.Rip:X16}");
                                                Console.WriteLine($"    RSP:      0x{ctx.Rsp:X16}");
                                                Console.WriteLine($"    Priority: {te.tpBasePri}");
                                                Console.WriteLine($"    PoolID:   0x{poolInfo.PoolId:X}");
                                                Console.ResetColor();
                                            }
                                        }
                                    }
                                }
                            }

                            Marshal.FreeHGlobal(infoPtr);
                        }
                        catch (Exception ex)
                        {
                            if (verbose)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"[!] Error checking thread {te.th32ThreadID}: {ex.Message}");
                                Console.ResetColor();
                            }
                        }
                        finally
                        {
                            CloseHandle(hThread);
                        }
                    }
                }
            }
            while (Thread32Next(snap, ref te));

            CloseHandle(snap);

            // ═══════════════════════════════════════════════════════
            // RESULTS SUMMARY
            // ═══════════════════════════════════════════════════════

            Console.WriteLine("\n╔═══════════════════════════════════════════════════╗");
            Console.WriteLine("║             SCAN RESULTS                          ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════╝");
            Console.WriteLine($"Total System Threads:    {totalThreads}");
            Console.WriteLine($"Target Process Threads:  {processThreads}");
            Console.WriteLine($"Pool Thread Candidates:  {poolCandidates}");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✓ Passed All Filters:    {poolThreads.Count}");
            Console.ResetColor();
            Console.WriteLine();

            if (poolThreads.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] No suitable pool threads found!");
                Console.WriteLine("[!] Recommendations:");
                Console.WriteLine("    - Try disabling alertableOnly filter");
                Console.WriteLine("    - Try disabling robloxHeuristics");
                Console.WriteLine("    - Wait a few seconds and retry (threads may be busy)");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[GARCEA]: Boss, am gasit {poolThreads.Count} thread pool gata de hijack!");
                Console.ResetColor();
            }

            return poolThreads;
        }

        // ═══════════════════════════════════════════════════════
        // HELPER: Check if thread is in wait state
        // ═══════════════════════════════════════════════════════

        private static bool IsThreadInWaitState(ulong rip)
        {
            // Get ntdll base address
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero) return false;

            ulong ntdllBase = (ulong)ntdll.ToInt64();
            ulong ntdllEnd = ntdllBase + 0x200000; // Approximate ntdll size

            // Check if RIP is in ntdll (common for waiting threads)
            if (rip >= ntdllBase && rip <= ntdllEnd)
            {
                // Thread is likely in a wait function
                return true;
            }

            // Could also check for specific wait function addresses
            // But this is good enough for our purposes
            return false;
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        // ═══════════════════════════════════════════════════════
        // ADVANCED: Pick the BEST thread to hijack
        // ═══════════════════════════════════════════════════════

        public static uint? SelectBestThread(List<uint> poolThreads, Process targetProcess)
        {
            if (poolThreads.Count == 0) return null;

            Console.WriteLine("\n[SELECT] Analyzing threads to find best hijack target...");

            Dictionary<uint, int> threadScores = new Dictionary<uint, int>();

            foreach (uint tid in poolThreads)
            {
                int score = 0;

                IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, tid);
                if (hThread != IntPtr.Zero)
                {
                    CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_FULL };
                    if (GetThreadContext(hThread, ref ctx))
                    {
                        // Prefer threads with TID in "sweet spot" (1000-5000)
                        if (tid > 1000 && tid < 5000) score += 10;

                        // Prefer threads in ntdll wait (more stable)
                        if (IsThreadInWaitState(ctx.Rip)) score += 20;

                        // Prefer threads with normal priority
                        ProcessThread pt = targetProcess.Threads.Cast<ProcessThread>()
                            .FirstOrDefault(t => t.Id == tid);
                        if (pt != null)
                        {
                            if (pt.PriorityLevel == ThreadPriorityLevel.Normal) score += 15;
                        }
                    }
                    CloseHandle(hThread);
                }

                threadScores[tid] = score;
            }

            // Select thread with highest score
            var best = threadScores.OrderByDescending(kvp => kvp.Value).First();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SELECT] ✓ Best thread: TID {best.Key} (score: {best.Value})");
            Console.ResetColor();

            return best.Key;
        }
    }
    class RoabaPipe
    {
        private static Thread pipeThread = null;
        private static bool isRunning = false;
        private static NamedPipeServerStream pipeServer = null;
        public volatile static bool pipeBusy = false;

        public static void StartPipeServer()
        {
            if (isRunning) return;
            isRunning = true;
            pipeThread = new Thread(() =>
            {
                while (isRunning)
                {
                    try
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.ResetColor();
                        pipeServer = new NamedPipeServerStream("RoabaX", PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                        pipeServer.WaitForConnection();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.ResetColor();
                        StreamReader reader = new StreamReader(pipeServer);
                        string command = reader.ReadToEnd();
                        if (!string.IsNullOrEmpty(command))
                            ExecutePipeCommand(command);
                        pipeServer.Close();
                    }
                    catch { }
                }
            });
            pipeThread.IsBackground = true;
            pipeThread.Start();
            pipeBusy = true;
        }

        public static void StopPipeServer()
        {
            isRunning = false;
            pipeBusy = false;
            if (pipeServer != null) try { pipeServer.Close(); } catch { }
            Console.WriteLine("[+] Tevi server oprit");
        }

        static void ExecutePipeCommand(string command)
        {
            try
            {
                string[] parts = command.Split(new[] { ':' }, 2);
                string cmd = parts[0].ToUpper();
                string data = parts.Length > 1 ? parts[1] : "";

                lock (RoabaX.ConsoleLock)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[PIPE] Executing: {cmd}");
                    Console.ResetColor();
                }

                switch (cmd)
                {
                    case "READ": PipeReadMemory(data); break;
                    case "WRITE": PipeWriteMemory(data); break;
                    case "SCAN": PipeScanValue(data); break;
                    case "PATTERN": PipePatternScan(data); break;
                    case "INFO": PipeProcessInfo(); break;
                    case "EXEC": break;
                    default:
                        lock (RoabaX.ConsoleLock) Console.WriteLine($"[!] Comanda proasta: {cmd}");
                        break;
                }
            }
            catch (Exception ex)
            {
                lock (RoabaX.ConsoleLock) Console.WriteLine($"[!] Baga baterii la telecomanda: {ex.Message}");
            }
        }

        static void PipeReadMemory(string data)
        {
            string[] parts = data.Split(',');
            if (parts.Length != 2) return;
            IntPtr address = (IntPtr)Convert.ToInt64(parts[0], 16);
            int size = int.Parse(parts[1]);
            byte[] buffer = new byte[size];
            RoabaX.ReadProcessMemory(RoabaX.processHandle, address, buffer, size, out int bytesRead);

            lock (RoabaX.ConsoleLock)
            {
                Console.WriteLine($"[PIPE] Am citit {bytesRead} bytes de la 0x{address.ToString("X")}");
                Console.Write("Data: ");
                for (int i = 0; i < Math.Min(bytesRead, 32); i++)
                    Console.Write($"{buffer[i]:X2} ");
                Console.WriteLine();
            }
        }

        static void PipeWriteMemory(string data)
        {
            string[] parts = data.Split(',');
            if (parts.Length != 3) return;
            IntPtr address = (IntPtr)Convert.ToInt64(parts[0], 16);
            string type = parts[1].ToUpper();
            string value = parts[2];
            byte[] dataToWrite = null;
            switch (type)
            {
                case "INT": dataToWrite = BitConverter.GetBytes(int.Parse(value)); break;
                case "FLOAT": dataToWrite = BitConverter.GetBytes(float.Parse(value)); break;
                case "BYTES":
                    string[] hexBytes = value.Split(' ');
                    dataToWrite = new byte[hexBytes.Length];
                    for (int i = 0; i < hexBytes.Length; i++)
                        dataToWrite[i] = Convert.ToByte(hexBytes[i], 16);
                    break;
            }
            if (dataToWrite != null)
            {
                uint oldProtect;
                RoabaX.VirtualProtectEx(RoabaX.processHandle, address, (UIntPtr)dataToWrite.Length, 0x40, out oldProtect);
                RoabaX.NtWriteVirtualMemory(RoabaX.processHandle, address, dataToWrite, (uint)dataToWrite.Length, out uint written);
                RoabaX.VirtualProtectEx(RoabaX.processHandle, address, (UIntPtr)dataToWrite.Length, oldProtect, out _);

                lock (RoabaX.ConsoleLock)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[PIPE] Scris {written} bytes la 0x{address.ToString("X")}");
                    Console.ResetColor();
                }
            }
        }

        static void PipeScanValue(string data)
        {
            int valueToFind = int.Parse(data);
            lock (RoabaX.ConsoleLock) Console.WriteLine($"[PIPE] Scanam pt valoare: {valueToFind}");

            List<IntPtr> results = new List<IntPtr>();
            byte[] valueBytes = BitConverter.GetBytes(valueToFind);
            IntPtr baseAddr = RoabaX.targetProcess.MainModule.BaseAddress;
            int moduleSize = RoabaX.targetProcess.MainModule.ModuleMemorySize;
            int chunkSize = 4096;
            byte[] buffer = new byte[chunkSize];
            for (long offset = 0; offset < moduleSize && results.Count < 10; offset += chunkSize - 3)
            {
                IntPtr currentAddress = baseAddr + (int)offset;
                RoabaX.ReadProcessMemory(RoabaX.processHandle, currentAddress, buffer, chunkSize, out int bytesRead);
                for (int i = 0; i < bytesRead - 3; i++)
                {
                    if (buffer[i] == valueBytes[0] && buffer[i + 1] == valueBytes[1] &&
                        buffer[i + 2] == valueBytes[2] && buffer[i + 3] == valueBytes[3])
                    {
                        results.Add(currentAddress + i);
                        if (results.Count >= 10) break;
                    }
                }
            }

            lock (RoabaX.ConsoleLock)
            {
                Console.WriteLine($"[PIPE] Found {results.Count} results:");
                foreach (var addr in results)
                    Console.WriteLine($" 0x{addr.ToString("X")}");
            }
        }

        static void PipePatternScan(string data)
        {
            lock (RoabaX.ConsoleLock) Console.WriteLine($"[PIPE] Pattern scanning: {data}");

            string[] patternParts = data.Split(' ');
            byte?[] pattern = new byte?[patternParts.Length];
            for (int i = 0; i < patternParts.Length; i++)
            {
                if (patternParts[i] == "??" || patternParts[i] == "?")
                    pattern[i] = null;
                else
                    pattern[i] = Convert.ToByte(patternParts[i], 16);
            }

            IntPtr baseAddr = RoabaX.targetProcess.MainModule.BaseAddress;
            int moduleSize = RoabaX.targetProcess.MainModule.ModuleMemorySize;
            int chunkSize = 4096;
            byte[] buffer = new byte[chunkSize];
            for (long offset = 0; offset < moduleSize; offset += chunkSize - pattern.Length)
            {
                IntPtr currentAddress = baseAddr + (int)offset;
                RoabaX.ReadProcessMemory(RoabaX.processHandle, currentAddress, buffer, chunkSize, out int bytesRead);
                for (int i = 0; i < bytesRead - pattern.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        if (pattern[j].HasValue && buffer[i + j] != pattern[j].Value)
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        lock (RoabaX.ConsoleLock)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[PIPE] Pattern found at: 0x{(currentAddress + i).ToString("X")}");
                            Console.ResetColor();
                        }
                        return;
                    }
                }
            }
            lock (RoabaX.ConsoleLock) Console.WriteLine("[PIPE] Pattern not found");
        }

        static void PipeProcessInfo()
        {
            lock (RoabaX.ConsoleLock)
            {
                Console.WriteLine($"[PIPE] Process Info:");
                Console.WriteLine($" Name: {RoabaX.targetProcess.ProcessName}");
                Console.WriteLine($" PID: {RoabaX.targetProcess.Id}");
                Console.WriteLine($" Base: 0x{RoabaX.targetProcess.MainModule.BaseAddress.ToString("X")}");
                Console.WriteLine($" Size: {RoabaX.targetProcess.MainModule.ModuleMemorySize / 1024 / 1024} MB");
            }
        }
    }


    class RoabaCube
    {
        private static bool spinEnabled = true;
        private static float A = 0, B = 0, C = 0;
        const int width = 40;
        const int height = 20;
        private static float[] zBuffer = new float[width * height];
        private static char[] buffer = new char[width * height];
        const char backgroundASCIICode = ' ';
        const int distanceFromCam = 60;
        const float K1 = 20;
        const float incrementSpeed = 0.8f;
        private static char frontChar = '&';
        private static char rightChar = '#';
        private static char leftChar = '~';
        private static char backChar = '$';
        private static char bottomChar = '+';
        private static char topChar = '*';

        private static Thread cubeThread = null;
        private static bool isRunning = false;

        private static void FillArray<T>(T[] array, T value)
        {
            for (int i = 0; i < array.Length; i++)
                array[i] = value;
        }

        public static void StartCube()
        {
            if (isRunning) return;
            isRunning = true;
            cubeThread = new Thread(() =>
            {
                int startX = Console.WindowWidth - width - 2;
                int startY = 1;
                while (isRunning)
                {
                    try
                    {
                        FillArray(buffer, backgroundASCIICode);
                        FillArray(zBuffer, 0f);
                        RenderCube(6, 0, "ROABA", 0);

                        lock (RoabaX.ConsoleLock)
                        {
                            int currentX = Console.WindowWidth - width - 2;
                            for (int y = 0; y < height; y++)
                            {
                                Console.SetCursorPosition(currentX, startY + y);
                                StringBuilder line = new StringBuilder(width);
                                for (int x = 0; x < width; x++)
                                    line.Append(buffer[x + y * width]);
                                Console.Write(line.ToString());
                            }
                        }

                        if (spinEnabled)
                        {
                            A += 0.05f;
                            B += 0.05f;
                            C += 0.02f;
                        }
                        Thread.Sleep(50);
                    }
                    catch { }
                }
            });
            cubeThread.IsBackground = true;
            cubeThread.Start();
        }

        public static void StopCube()
        {
            isRunning = false;
            if (cubeThread != null) cubeThread.Join(1000);

            lock (RoabaX.ConsoleLock)
            {
                try
                {
                    int startX = Console.WindowWidth - width - 2;
                    for (int y = 0; y < height; y++)
                    {
                        Console.SetCursorPosition(startX, 1 + y);
                        Console.Write(new string(' ', width));
                    }
                }
                catch { }
            }
        }

        private static void RenderCube(float cubeWidth, float horizontalOffset, string text, int yOffset)
        {
            for (float cubeX = -cubeWidth; cubeX < cubeWidth; cubeX += incrementSpeed)
                for (float cubeY = -cubeWidth; cubeY < cubeWidth; cubeY += incrementSpeed)
                {
                    DrawFace(cubeX, cubeY, -cubeWidth, frontChar, horizontalOffset, yOffset);
                    DrawFace(cubeWidth, cubeY, cubeX, rightChar, horizontalOffset, yOffset);
                    DrawFace(-cubeWidth, cubeY, -cubeX, leftChar, horizontalOffset, yOffset);
                    DrawFace(-cubeX, cubeY, cubeWidth, backChar, horizontalOffset, yOffset);
                    DrawFace(cubeX, -cubeWidth, -cubeY, bottomChar, horizontalOffset, yOffset);
                    DrawFace(cubeX, cubeWidth, cubeY, topChar, horizontalOffset, yOffset);
                }

            float textZ = -cubeWidth;
            float charSpacing = 2.8f;
            float totalWidth = (text.Length - 1) * charSpacing;
            float startLocalX = -totalWidth / 2f;
            for (int i = 0; i < text.Length; i++)
            {
                float localX = startLocalX + i * charSpacing;
                float localY = 0f;
                float x = CalculateX(localX, localY, textZ);
                float y = CalculateY(localX, localY, textZ);
                float z = CalculateZ(localX, localY, textZ) + distanceFromCam;
                if (z <= 0) continue;
                float ooz = 1 / z; ooz += 0.001f;
                int xp = (int)(width / 2 + horizontalOffset + K1 * ooz * x * 2);
                int yp = (int)(height / 2 + yOffset + K1 * ooz * y);
                if (xp >= 0 && xp < width && yp >= 0 && yp < height)
                {
                    int idx = xp + yp * width;
                    if (ooz >= zBuffer[idx])
                    {
                        zBuffer[idx] = ooz;
                        buffer[idx] = text[i];
                    }
                }
            }
        }

        private static void DrawFace(float cubeX, float cubeY, float cubeZ, char ch, float horizontalOffset, int yOffset)
        {
            float x = CalculateX(cubeX, cubeY, cubeZ);
            float y = CalculateY(cubeX, cubeY, cubeZ);
            float z = CalculateZ(cubeX, cubeY, cubeZ) + distanceFromCam;
            if (z <= 0) return;
            float ooz = 1 / z;
            int xp = (int)(width / 2 + horizontalOffset + K1 * ooz * x * 2);
            int yp = (int)(height / 2 + yOffset + K1 * ooz * y);
            if (xp >= 0 && xp < width && yp >= 0 && yp < height)
            {
                int idx = xp + yp * width;
                if (ooz > zBuffer[idx])
                {
                    zBuffer[idx] = ooz;
                    buffer[idx] = ch;
                }
            }
        }

        private static float CalculateX(float i, float j, float k) =>
            j * (float)Math.Sin(A) * (float)Math.Sin(B) * (float)Math.Cos(C) -
            k * (float)Math.Cos(A) * (float)Math.Sin(B) * (float)Math.Cos(C) +
            j * (float)Math.Cos(A) * (float)Math.Sin(C) +
            k * (float)Math.Sin(A) * (float)Math.Sin(C) +
            i * (float)Math.Cos(B) * (float)Math.Cos(C);

        private static float CalculateY(float i, float j, float k) =>
            j * (float)Math.Cos(A) * (float)Math.Cos(C) +
            k * (float)Math.Sin(A) * (float)Math.Cos(C) -
            j * (float)Math.Sin(A) * (float)Math.Sin(B) * (float)Math.Sin(C) +
            k * (float)Math.Cos(A) * (float)Math.Sin(B) * (float)Math.Sin(C) -
            i * (float)Math.Cos(B) * (float)Math.Sin(C);

        private static float CalculateZ(float i, float j, float k) =>
            k * (float)Math.Cos(A) * (float)Math.Cos(B) -
            j * (float)Math.Sin(A) * (float)Math.Cos(B) +
            i * (float)Math.Sin(B);
    }

    class RoabaUnprotect
    {
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
        const uint MEM_COMMIT = 0x1000; const uint MEM_RESERVE = 0x2000; const uint MEM_RELEASE = 0x8000; const uint PAGE_EXECUTE_READWRITE = 0x40;

        public static IntPtr UnprotectFunction(IntPtr processHandle, IntPtr functionAddr, int maxSize = 256)
        {
            try
            {
                Console.WriteLine($"\n[+] Unprotecting function at 0x{functionAddr.ToString("X")}...");
                byte[] originalBytes = new byte[maxSize];
                RoabaX.ReadProcessMemory(processHandle, functionAddr, originalBytes, maxSize, out int bytesRead);
                int funcSize = FindFunctionSize(originalBytes, maxSize);
                if (funcSize == 0)
                {
                    Console.WriteLine("[!] Could not determine function size");
                    return functionAddr;
                }
                Console.WriteLine($"[+] Function size: {funcSize} bytes");
                IntPtr newFunc = VirtualAlloc(IntPtr.Zero, (uint)funcSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (newFunc == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Failed to allocate memory");
                    return functionAddr;
                }
                Console.WriteLine($"[+] Allocated at 0x{newFunc.ToString("X")}");
                Marshal.Copy(originalBytes, 0, newFunc, funcSize);
                int patchCount = PatchSecurityChecks(newFunc, funcSize);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Function unprotected! Patched {patchCount} security checks 🎉");
                Console.ResetColor();
                return newFunc;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Unprotect failed: {ex.Message}");
                return functionAddr;
            }
        }

        static int FindFunctionSize(byte[] bytes, int maxSize)
        {
            for (int i = 16; i < maxSize - 2; i++)
            {
                if (bytes[i] == 0x48 && bytes[i + 1] == 0x83 && bytes[i + 2] == 0xC4 && i + 4 < maxSize && bytes[i + 4] == 0xC3)
                    return i + 5;
                if (bytes[i] == 0x5D && bytes[i + 1] == 0xC3)
                    return i + 2;
                if (bytes[i] == 0xC3 && i > 32)
                    return i + 1;
            }
            return 0;
        }

        static int PatchSecurityChecks(IntPtr funcAddr, int size)
        {
            byte[] bytes = new byte[size];
            Marshal.Copy(funcAddr, bytes, 0, size);
            int patchCount = 0;
            for (int i = 0; i < size - 7; i++)
            {
                if (bytes[i] == 0x72 && i + 7 < size && bytes[i + 2] == 0xA1 && bytes[i + 7] == 0x8B)
                {
                    Console.WriteLine($" [*] Found security check at offset +0x{i:X} (Axon pattern)");
                    bytes[i] = 0xEB;
                    patchCount++;
                }
                if (bytes[i] == 0xCC)
                {
                    Console.WriteLine($" [*] Found INT3 at offset +0x{i:X}");
                    bytes[i] = 0x90;
                    patchCount++;
                }
            }
            if (patchCount > 0)
                Marshal.Copy(bytes, 0, funcAddr, size);
            return patchCount;
        }
    }

    class RoabaAdvancedScan
    {
        public static IntPtr ScanWithOffset(IntPtr processHandle, Process targetProcess, string pattern, int returnOffset = 0)
        {
            Console.WriteLine($"\n[+] Advanced pattern scan: {pattern}");
            Console.WriteLine($"[+] Return offset: +{returnOffset}");
            IntPtr result = PatternScanBase(processHandle, targetProcess, pattern);
            if (result != IntPtr.Zero && returnOffset != 0)
            {
                byte[] offsetBytes = new byte[4];
                RoabaX.ReadProcessMemory(processHandle, result + returnOffset, offsetBytes, 4, out _);
                int relativeOffset = BitConverter.ToInt32(offsetBytes, 0);
                IntPtr absoluteAddr = result + returnOffset + 4 + relativeOffset;
                Console.WriteLine($"[+] Pattern found at: 0x{result.ToString("X")}");
                Console.WriteLine($"[+] Relative offset: 0x{relativeOffset:X}");
                Console.WriteLine($"[+] Absolute address: 0x{absoluteAddr.ToString("X")}");
                return absoluteAddr;
            }
            return result;
        }

        static IntPtr PatternScanBase(IntPtr processHandle, Process targetProcess, string pattern)
        {
            string[] patternParts = pattern.Split(' ');
            byte?[] patternBytes = new byte?[patternParts.Length];
            for (int i = 0; i < patternParts.Length; i++)
            {
                if (patternParts[i] == "??" || patternParts[i] == "?")
                    patternBytes[i] = null;
                else
                    patternBytes[i] = Convert.ToByte(patternParts[i], 16);
            }
            IntPtr baseAddr = targetProcess.MainModule.BaseAddress;
            int moduleSize = targetProcess.MainModule.ModuleMemorySize;
            int chunkSize = 4096;
            byte[] buffer = new byte[chunkSize];
            for (long offset = 0; offset < moduleSize; offset += chunkSize - patternBytes.Length)
            {
                IntPtr currentAddress = baseAddr + (int)offset;
                RoabaX.ReadProcessMemory(processHandle, currentAddress, buffer, chunkSize, out int bytesRead);
                for (int i = 0; i < bytesRead - patternBytes.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < patternBytes.Length; j++)
                    {
                        if (patternBytes[j].HasValue && buffer[i + j] != patternBytes[j].Value)
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return currentAddress + i;
                }
            }
            return IntPtr.Zero;
        }
    }

    // ============================================
    // anti anti-cheat pro max ultra mega
    // ============================================
    class AntiByfronUltra //nu pt roblox :) [not for roblox]
    {
        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")]
        static extern int NtSetInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength);

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public static void SpoofProcessName()
        {
            string[] legitimateNames =
            {
                "svchost.exe",
                "RuntimeBroker.exe",
                "SearchIndexer.exe",
                "dwm.exe",
                "audiodg.exe",
                "sihost.exe"
            };

            Random rng = new Random();
            string newName = legitimateNames[rng.Next(legitimateNames.Length)];

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[STEALTH] Disguised as: {newName}"); //placeholder, TODO: add actual spoofing if possible with no kernel drivers
            Console.ResetColor();
        }

        private static List<string> BlacklistedProcesses = new List<string>
        {
            "cheatengine", "processhacker", "x64dbg", "x32dbg",
            "ida", "ollydbg", "wireshark", "fiddler", "httpdebugger",
            "procmon", "procexp", "ramcapture", "memoryze"
        };

        public static bool DetectSuspiciousProcesses()
        {
            foreach (var proc in Process.GetProcesses())
            {
                string name = proc.ProcessName.ToLower();
                if (BlacklistedProcesses.Any(bp => name.Contains(bp)))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] WARNING: {proc.ProcessName} detected!");
                    Console.ResetColor();
                    return true;
                }
            }
            return false;
        }

        [DllImport("ntdll.dll")]
        static extern int NtSetInformationObject(IntPtr handle, int objectInformationClass, IntPtr objectInformation, uint objectInformationLength);

        public static void ProtectHandles(IntPtr targetHandle)
        {
            const int ObjectHandleFlagInformation = 4;
            IntPtr flagInfo = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(flagInfo, 1);

            NtSetInformationObject(targetHandle, ObjectHandleFlagInformation, flagInfo, 4);
            Marshal.FreeHGlobal(flagInfo);

            Console.WriteLine("[STEALTH] Handle protection enabled");
        }

        public static byte[] EncryptPayload(byte[] data)
        {
            Random rng = new Random();
            byte key = (byte)rng.Next(1, 255);

            byte[] encrypted = new byte[data.Length + 1];
            encrypted[0] = key;

            for (int i = 0; i < data.Length; i++)
            {
                encrypted[i + 1] = (byte)(data[i] ^ key ^ (i & 0xFF));
            }

            return encrypted;
        }

        public static byte[] DecryptPayload(byte[] data)
        {
            if (data.Length < 2) return data;

            byte key = data[0];
            byte[] decrypted = new byte[data.Length - 1];

            for (int i = 0; i < decrypted.Length; i++)
            {
                decrypted[i] = (byte)(data[i + 1] ^ key ^ (i & 0xFF));
            }

            return decrypted;
        }

        public static byte[] GeneratePolymorphicWrapper(byte[] originalCode)
        {
            List<byte> poly = new List<byte>();
            Random rng = new Random();

            byte[][] junkInstructions =
            {
                new byte[] { 0x90 },
                new byte[] { 0x50, 0x58 },
                new byte[] { 0x48, 0x31, 0xC0 },
                new byte[] { 0x48, 0x89, 0xC0 },
                new byte[] { 0x48, 0x87, 0xC0 },
                new byte[] { 0x90, 0x90 },
            };

            for (int junkCount = 0; junkCount < rng.Next(5, 15); junkCount++)
            {
                poly.AddRange(junkInstructions[rng.Next(junkInstructions.Length)]);
            }

            foreach (byte b in originalCode)
            {
                if (rng.Next(100) < 20)
                {
                    poly.AddRange(junkInstructions[rng.Next(junkInstructions.Length)]);
                }
                poly.Add(b);
            }

            return poly.ToArray();
        }

        [DllImport("kernel32.dll")]
        static extern bool IsProcessorFeaturePresent(int processorFeature);

        const int PF_VIRT_FIRMWARE_ENABLED = 21;

        public static bool DetectHypervisor()
        {
            if (IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED))
            {
                Console.WriteLine("[!] Hypervisor detected (method 1)");
                return true;
            }

            string[] vmArtifacts =
            {
                "VMware", "VirtualBox", "VBOX", "QEMU", "Xen", "Hyper-V"
            };

            foreach (var artifact in vmArtifacts)
            {
                if (Environment.GetEnvironmentVariable("COMPUTERNAME")?.Contains(artifact) == true)
                {
                    Console.WriteLine($"[!] VM artifact detected: {artifact}");
                    return true;
                }
            }

            return false;
        }

        [DllImport("user32.dll")]
        static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);

        [DllImport("user32.dll")]
        static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

        public static void EnableAntiScreenshot()
        {
            IntPtr robloxWindow = FindWindow(null, "Roblox");
            if (robloxWindow != IntPtr.Zero)
            {
                SetWindowDisplayAffinity(robloxWindow, WDA_EXCLUDEFROMCAPTURE);
                Console.WriteLine("[STEALTH] Anti-screenshot enabled");
            }
        }

        [DllImport("ntdll.dll")]
        static extern int NtCreateSection(
            out IntPtr sectionHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            ref long maximumSize,
            uint sectionPageProtection,
            uint allocationAttributes,
            IntPtr fileHandle
        );

        [DllImport("ntdll.dll")]
        static extern int NtMapViewOfSection(
            IntPtr sectionHandle,
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            IntPtr commitSize,
            ref long sectionOffset,
            ref long viewSize,
            uint inheritDisposition,
            uint allocationType,
            uint win32Protect
        );

        const uint SECTION_MAP_READ = 0x0004;
        const uint SECTION_MAP_WRITE = 0x0002;
        const uint SECTION_MAP_EXECUTE = 0x0008;
        const uint SEC_COMMIT = 0x08000000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        public static IntPtr InjectViaSection(IntPtr hProcess, byte[] dllBytes)
        {
            Console.WriteLine("[+] Starting section-based injection...");

            try
            {
                byte[] encrypted = EncryptPayload(dllBytes);
                byte[] poly = GeneratePolymorphicWrapper(encrypted);

                long sectionSize = poly.Length;
                int status = NtCreateSection(
                    out IntPtr hSection,
                    SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                    IntPtr.Zero,
                    ref sectionSize,
                    PAGE_EXECUTE_READWRITE,
                    SEC_COMMIT,
                    IntPtr.Zero
                );

                if (status != 0)
                {
                    Console.WriteLine($"[-] NtCreateSection failed: 0x{status:X}");
                    return IntPtr.Zero;
                }

                IntPtr localBase = IntPtr.Zero;
                long localViewSize = 0;
                long localOffset = 0;

                status = NtMapViewOfSection(
                    hSection,
                    Process.GetCurrentProcess().Handle,
                    ref localBase,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref localOffset,
                    ref localViewSize,
                    2,
                    0,
                    PAGE_EXECUTE_READWRITE
                );

                if (status != 0)
                {
                    Console.WriteLine($"[-] Local map failed: 0x{status:X}");
                    return IntPtr.Zero;
                }

                Marshal.Copy(poly, 0, localBase, poly.Length);

                IntPtr remoteBase = IntPtr.Zero;
                long remoteViewSize = 0;
                long remoteOffset = 0;

                status = NtMapViewOfSection(
                    hSection,
                    hProcess,
                    ref remoteBase,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref remoteOffset,
                    ref remoteViewSize,
                    2,
                    0,
                    PAGE_EXECUTE_READWRITE
                );

                if (status != 0)
                {
                    Console.WriteLine($"[-] mapa cu telecomand a dat fail: 0x{status:X}");
                    return IntPtr.Zero;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"mapat la: 0x{remoteBase:X}");
                Console.ResetColor();

                return remoteBase;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Section injection failed: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        [DllImport("ntdll.dll")]
        static extern int NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList
        );

        public static IntPtr CreateStealthThread(IntPtr hProcess, IntPtr startAddress, IntPtr parameter)
        {
            const uint THREAD_ALL_ACCESS = 0x1FFFFF;

            int status = NtCreateThreadEx(
                out IntPtr hThread,
                THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hProcess,
                startAddress,
                parameter,
                false,
                0, 0, 0,
                IntPtr.Zero
            );

            if (status == 0)
            {
                Console.WriteLine("Created stealth thread");
                return hThread;
            }

            return IntPtr.Zero;
        }

        public static void InitializeStealth(IntPtr processHandle)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n╔═══════════════════════════════════════╗");
            Console.WriteLine("║       ROABA ULTRA PICTAT INIT          ║");
            Console.WriteLine("╚═══════════════════════════════════════╝\n");
            Console.ResetColor();

            Console.Write("[1/7] Verificam pt anti-roaba... ");
            if (DetectSuspiciousProcesses())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Proces suspicios detektat");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Nu eggzista procese suspicioase");
                Console.ResetColor();
            }

            Console.Write("[2/7] Verif pt camere de supraveghere... ");
            if (DetectHypervisor())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("DETEKTAT");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Nu is cam. de supraveghere");
                Console.ResetColor();
            }

            Console.Write("[3/7] Pictam roaba... ");
            SpoofProcessName();

            Console.Write("[4/7] Protejam roaba de pietre... ");
            ProtectHandles(processHandle);

            Console.Write("[5/7] Anti poze la roaba (anti paparazzi)... ");
            EnableAntiScreenshot();

            Console.Write("[6/7] Encriptiones initialized... ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("gata bos");
            Console.ResetColor();

            Console.Write("[7/7] Motor 4D initializat... ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("gata bos");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n[+] Roaba Pictata activated");
            Console.WriteLine("[+] ROABA PICTATA SUCCESSFULY!");
            Console.WriteLine("[+] ez");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
    // main
    class RoabaX
    {
        public static readonly object ConsoleLock = new object();

        [DllImport("ntdll.dll")]
        public static extern uint NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint BufferSize,
            out uint ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint RegionSize,
            uint NewProtect,
            out uint OldProtect
        );

        [DllImport("ntdll.dll")]
        public static extern uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref uint RegionSize,
            uint AllocationType,
            uint Protect
        );

        [DllImport("ntdll.dll")]
        public static extern uint NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref uint RegionSize,
            uint FreeType
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READWRITE = 0x04;

        public static IntPtr processHandle = IntPtr.Zero;
        public static Process targetProcess = null;

        public static bool StealthWrite(IntPtr address, byte[] data)
        {
            uint written = 0;
            uint size = (uint)data.Length;
            uint status = NtWriteVirtualMemory(processHandle, address, data, size, out written);
            return status == 0 && written == size;
        }

        public static bool StealthProtect(IntPtr address, uint size, uint newProtect, out uint oldProtect)
        {
            oldProtect = 0;
            IntPtr baseAddr = address;
            uint regionSize = size;
            uint status = NtProtectVirtualMemory(processHandle, ref baseAddr, ref regionSize, newProtect, out oldProtect);
            return status == 0;
        }
        public static IntPtr StealthAlloc(uint size, uint protect = 0x04)  // ← default to PAGE_READWRITE instead of 0x40
        {
            IntPtr baseAddr = IntPtr.Zero;
            uint regionSize = size;
            uint status = NtAllocateVirtualMemory(processHandle, ref baseAddr, IntPtr.Zero, ref regionSize, 0x3000, protect);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[ALLOC] NtAllocateVirtualMemory(size={size:X}, protect=0x{protect:X}) → NTSTATUS 0x{status:X8}");

            if (status != 0)
            {
                string msg = status switch
                {
                    0xC0000022 => "Access Denied (Hyperion blocked RWX alloc)",
                    0xC0000005 => "Access Violation / bad handle/pointer",
                    0xC00000F0 => "Invalid Parameter",
                    0xC0000018 => "Already Committed / conflict",
                    _ => $"Unknown error (check NTSTATUS docs)"
                };
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ALLOC FAIL] {msg}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[ALLOC OK] → 0x{baseAddr.ToString("X")}");
                Console.ResetColor();
            }

            return status == 0 ? baseAddr : IntPtr.Zero;
        }

        class RoabaBurlan
        {
            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

            [DllImport("kernel32.dll")]
            public static extern uint SuspendThread(IntPtr hThread);

            [DllImport("kernel32.dll")]
            public static extern uint ResumeThread(IntPtr hThread);

            [DllImport("kernel32.dll")]
            public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

            [DllImport("kernel32.dll")]
            public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);

            [StructLayout(LayoutKind.Sequential)]
            public struct CONTEXT64
            {
                public ulong P1Home; public ulong P2Home; public ulong P3Home; public ulong P4Home;
                public ulong P5Home; public ulong P6Home;
                public uint ContextFlags; public uint MxCsr;
                public ushort SegCs; public ushort SegDs; public ushort SegEs; public ushort SegFs;
                public ushort SegGs; public ushort SegSs;
                public uint EFlags;
                public ulong Dr0; public ulong Dr1; public ulong Dr2; public ulong Dr3;
                public ulong Dr6; public ulong Dr7;
                public ulong Rax; public ulong Rcx; public ulong Rdx; public ulong Rbx;
                public ulong Rsp; public ulong Rbp; public ulong Rsi; public ulong Rdi;
                public ulong R8; public ulong R9; public ulong R10; public ulong R11;
                public ulong R12; public ulong R13; public ulong R14; public ulong R15;
                public ulong Rip;
            }

            const uint THREAD_ALL_ACCESS = 0x1F03FF;
            const uint CONTEXT_ALL = 0x10000F;

            static readonly byte[] Shellcode = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, <dllMain>
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, <dllBase>
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                    // mov rdx, 1
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,                    // mov r8, 0
            0xFF, 0xD0,                                                   // call rax
            0xC3                                                          // ret
            };

            public static bool InjectBurlan(IntPtr processHandle, Process targetProcess, string dllPath)
            {
                if (!File.Exists(dllPath))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] DLL not found");
                    Console.ResetColor();
                    return false;
                }

                byte[] dllBytes = File.ReadAllBytes(dllPath);
                Console.WriteLine($"[BURLAN] DLL Size: {dllBytes.Length} bytes");

                // Allocate memory for DLL
                IntPtr allocated = RoabaX.StealthAlloc((uint)dllBytes.Length + 0x1000);
                if (allocated == IntPtr.Zero)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Allocation failed");
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] Allocated at: 0x{allocated:X}");

                Console.WriteLine("[BURLAN] DLL written successfully");

                // Get entry point
                int peOffset = BitConverter.ToInt32(dllBytes, 0x3C);
                int entryPointRVA = BitConverter.ToInt32(dllBytes, peOffset + 0x28);
                IntPtr dllMain = allocated + entryPointRVA;

                Console.WriteLine($"[BURLAN] Entry Point: 0x{dllMain:X}");

                // Prepare shellcode
                byte[] sc = (byte[])Shellcode.Clone();
                BitConverter.GetBytes(dllMain.ToInt64()).CopyTo(sc, 2);      // mov rax, dllMain
                BitConverter.GetBytes(allocated.ToInt64()).CopyTo(sc, 12);    // mov rcx, dllBase

                // Write shellcode after DLL
                IntPtr shellAddr = allocated + dllBytes.Length;
                if (!RoabaX.StealthWrite(shellAddr, sc))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Shellcode write failed");
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] Shellcode at: 0x{shellAddr:X}");

                // Get threads
                var threads = new List<uint>();
                foreach (ProcessThread t in targetProcess.Threads)
                    threads.Add((uint)t.Id);

                if (threads.Count == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] No threads found");
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] Found {threads.Count} threads, using first one");

                // Open thread
                IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, threads[0]);
                if (hThread == IntPtr.Zero)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] OpenThread failed: {Marshal.GetLastWin32Error()}");
                    Console.ResetColor();
                    return false;
                }

                // Suspend thread
                uint suspendResult = SuspendThread(hThread);
                if (suspendResult == uint.MaxValue)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] SuspendThread failed: {Marshal.GetLastWin32Error()}");
                    CloseHandle(hThread);
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] Thread {threads[0]} suspended (suspend count: {suspendResult})");

                // Get context
                CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_ALL };
                if (!GetThreadContext(hThread, ref ctx))
                {
                    Console.WriteLine($"[-] GetThreadContext failed: {Marshal.GetLastWin32Error()}");
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    return false;
                }
                bool success = GetThreadContext(hThread, ref ctx);
                if (!success)
                {
                    int err = Marshal.GetLastWin32Error(); // MUST be right after the call
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] GetThreadContext failed with Win32 error: {err} (5=AccessDenied, 998=InvalidAccess, 87=BadParam)");
                    Console.ResetColor();

                    // Optional: more info
                    if (err == 5 || err == 998)
                        Console.WriteLine("    → Thread is likely protected by Byfron or Windows (common on Roblox)");

                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    return false;
                }
                Console.WriteLine($"[BURLAN] Old RIP: 0x{ctx.Rip:X} | RSP: 0x{ctx.Rsp:X}");

                // Push old RIP to stack
                ctx.Rsp -= 8;
                byte[] oldRipBytes = BitConverter.GetBytes(ctx.Rip);
                if (!RoabaX.StealthWrite((IntPtr)ctx.Rsp, oldRipBytes))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Failed to push old RIP to stack");
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] Pushed old RIP to stack at 0x{ctx.Rsp:X}");

                // Set new RIP to shellcode
                ctx.Rip = (ulong)shellAddr.ToInt64();

                // Set context
                if (!SetThreadContext(hThread, ref ctx))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] SetThreadContext failed: {err}");
                    if (err == 998)
                        Console.WriteLine("[-] Error 998 = NOACCESS - thread is protected!");
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine($"[BURLAN] New RIP: 0x{ctx.Rip:X}");

                // Resume thread
                ResumeThread(hThread);
                CloseHandle(hThread);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[BURLAN] ✅ INJECTION SUCCESSFUL!");
                Console.WriteLine($"[BURLAN] Mapped @ 0x{allocated:X}");
                Console.WriteLine($"[BURLAN] Hijacked thread {threads[0]}");
                Console.WriteLine($"[BURLAN] DllMain will execute on next thread wake");
                Console.ResetColor();

                return true;
            }
        }
        
        
        static void SendPipeCommand(string command)
        {
            try
            {
                using (var client = new NamedPipeClientStream(".", "RoabaX", PipeDirection.InOut))
                {
                    client.Connect(3000);
                    using (var writer = new StreamWriter(client) { AutoFlush = true })
                        writer.Write(command);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Eroare la trimitere: {ex.Message}");
            }
        }

        static void BurlanServerMenu()
        {
            Console.WriteLine("\n╔═════════════════════════════════════════╗");
            Console.WriteLine("║ 🚰     ROABA BURLAN CLIENT MODE 🚰       ║");
            Console.WriteLine("╚═════════════════════════════════════════╝");

            RoabaPipe.StartPipeServer();
            Console.WriteLine("[+] Server pornit! Scrie comenzi (HELP pentru exemple, EXIT sa revii la menu)");

            while (true)
            {
                Console.Write("ROABA> ");
                string input = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(input)) continue;

                if (input.ToUpper() == "EXIT")
                {
                    RoabaPipe.StopPipeServer();
                    Console.WriteLine("[+] Server oprit. Revenim la menu...");
                    break;
                }

                if (input.ToUpper() == "HELP" || input.ToUpper() == "EXAMPLES")
                {
                    ShowBurlanExamples();
                    continue;
                }

                SendPipeCommand(input);
            }
        }

        static void ShowBurlanExamples()
        {
            Console.WriteLine("\n📖 Exemple comenzi:\n");
            Console.WriteLine("READ:7FF612340000,64");
            Console.WriteLine("WRITE:7FF612340000,INT,1337");
            Console.WriteLine("WRITE:7FF612340000,FLOAT,99.5");
            Console.WriteLine("WRITE:7FF612340000,BYTES,90 90 90");
            Console.WriteLine("SCAN:100");
            Console.WriteLine("PATTERN:48 8B 05 ?? ?? ?? ??");
            Console.WriteLine("INFO");
            Console.WriteLine("\nEXIT  → revine la menu");
        }

        static void Main()
        {
            ShowSplashScreen();
            //RoabaCube.StartCube(); // Uncomment if you want the cube (kinda buggy rn) [e buguit]

            try
            {
                Process[] allProcesses = Process.GetProcesses();
                Console.WriteLine("🛞 Vezi care vrei sal strici de acilea (procese):\n");

                for (int i = 0; i < allProcesses.Length; i++)
                {
                    try
                    {
                        if (!string.IsNullOrEmpty(allProcesses[i].ProcessName))
                            Console.WriteLine($"[{i}] {allProcesses[i].ProcessName} (PID: {allProcesses[i].Id})");
                    }
                    catch { }
                }

                Console.Write("\n🪣 ia, care-l vrei? (numaru ala din stanga): ");
                int index = int.Parse(Console.ReadLine());
                targetProcess = allProcesses[index];

                Console.WriteLine($"\n[+] stai putin bag procesu in roaba: {targetProcess.ProcessName} ...");
                Thread.Sleep(500);

                processHandle = OpenProcess(
                    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                    false,
                    targetProcess.Id
                );

                if (processHandle == IntPtr.Zero)
                {
                    WheelFellOff($"Failed to load {targetProcess.ProcessName}");
                    //RoabaCube.StopCube();
                    return;
                }

                Console.WriteLine($"[+] ok bn am bagat prostia in roaba (vezi sa nu iti scape roaba) Handel: 0x{processHandle.ToString("X")}");
                Console.WriteLine($"[+] Base address: 0x{targetProcess.MainModule.BaseAddress.ToString("X")}");

                // ✨ initializare galeata cu var ✨
                AntiByfronUltra.InitializeStealth(processHandle);

                bool running = true;
                while (running)
                {
                    Console.WriteLine("\n╔════════════════════════════════════════╗");
                    Console.WriteLine("║    ROABA X ULTRA - STEALTH EDITION  ║");
                    Console.WriteLine("╚════════════════════════════════════════╝");
                    Console.WriteLine("[1]  Citeste memorie");
                    Console.WriteLine("[2]  Scrie memorie");
                    Console.WriteLine("[3]  Skaneaza ca aia din star trek pt o valoare");
                    Console.WriteLine("[4]  Pattern scan (AOB ca profesionistii)");
                    Console.WriteLine("[5]  ROABA TURBO");
                    Console.WriteLine("[6]  Tevi server (Executie cu telecomanda)");
                    Console.WriteLine("[7]  INJECT STEALTH (XENO Method)");
                    Console.WriteLine("[8]  Parkeaza Roaba");
                    Console.Write("\n🔧 Choice: ");

                    string choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1": ReadMemory(); break;
                        case "2": WriteMemory(); break;
                        case "3": ScanForValue(); break;
                        case "4": PatternScan(); break;
                        case "5": AdvancedMode(); break;
                        case "6": BurlanServerMenu(); break;
                        case "7": InjectStealth(); break; //nou oferta la coaiefland
                        case "8": running = false; break;
                        default: AxleSqueaking("Ai bagat adresa de memorie/bytesi in loc de optiune?"); break;
                    }
                }

                CloseHandle(processHandle);
                Console.WriteLine("\n[+] roaba a fost parkata in boschetsi successfuly");
            }
            catch (IndexOutOfRangeException)
            {
                TippedOver("Ia zi ceai scris prost");
            }
            catch (OutOfMemoryException)
            {
                LoadTooHeavy("Nu mai avem spatiu in roaba");
            }
            catch (Exception ex)
            {
                TippedOver($"'nu stim' de ce tia cazut roaba: {ex.Message}");
            }
            finally
            {
                //RoabaCube.StopCube();
            }

            Console.WriteLine("\n🛞 press any key sa nu iti ia tigani roaba...");
            Console.ReadKey();
        }
        static void InjectStealth()
        {
            Console.WriteLine("\n╔═══════════════════════════════════════════════════╗");
            Console.WriteLine("║    🛞 ROABA X - ADVANCED INJECTION 🛞            ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════╝\n");

            Console.Write("[?] Path to DLL (default: TrabantXEngine.dll): ");
            string dllPath = Console.ReadLine();
            if (string.IsNullOrEmpty(dllPath))
                dllPath = "TrabantXEngine.dll";

            if (!File.Exists(dllPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] DLL not found!");
                Console.ResetColor();
                return;
            }

            Console.WriteLine("\n[GARCEA]: Boss, alege metoda de injectie:");
            Console.WriteLine("[1] Thread Pool APC (★★★★☆ - Xeno/Wave style)");
            Console.WriteLine("[2] Thread Hijacking (★★★★☆ - Burlan style)");
            Console.WriteLine("[3] Simple CreateRemoteThread (★★☆☆☆ - detected fast)");
            Console.WriteLine("[4] Debug Mode (vezi tot procesul)");
            Console.Write("\nAlege (1-4): ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    InjectViaThreadPoolAPC(dllPath);
                    break;
                case "2":
                    InjectViaBurlan(dllPath);
                    break;
                case "3":
                    InjectSimple(dllPath);
                    break;
                case "4":
                    InjectDebug(dllPath);
                    break;
                default:
                    Console.WriteLine("[!] Invalid choice, using Thread Pool APC...");
                    InjectViaThreadPoolAPC(dllPath);
                    break;
            }
        }

        // ═══════════════════════════════════════════════════════
        // METHOD 1: THREAD POOL APC (XENO/WAVE STYLE) ★★★★☆
        // ═══════════════════════════════════════════════════════
        static void InjectViaThreadPoolAPC(string dllPath)
        {
            Console.WriteLine("\n[GARCEA]: Boss, folosim Thread Pool APC ca la Xeno!");
            Console.WriteLine("[GARCEA]: Cel mai sigur mod!\n");

            // Random delay before starting (anti-pattern detection)
            Thread.Sleep(new Random().Next(400, 1200));

            // Load DLL
            byte[] dllBytes = File.ReadAllBytes(dllPath);
            Console.WriteLine($"[+] DLL Size: {dllBytes.Length} bytes");

            // Validate PE
            if (!ValidatePE(dllBytes, out int peOffset, out int entryPointRVA, out int imageSize))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Invalid PE file!");
                Console.ResetColor();
                return;
            }

            Console.WriteLine($"[+] Entry Point RVA: 0x{entryPointRVA:X}");
            Console.WriteLine($"[+] Image Size: {imageSize} bytes");

            // Step 1: Find thread pools
            Console.WriteLine("\n[STEP 1/4] Scanning for thread pools...");
            Thread.Sleep(new Random().Next(300, 800)); // small delay before scan

            List<uint> poolThreads = AdvancedThreadPoolDetector.FindAdvancedThreadPools(
                targetProcess,
                alertableOnly: true,
                robloxHeuristics: true,
                verbose: true
            );

            if (poolThreads.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[!] No alertable pools found! Retrying relaxed...");
                Console.ResetColor();
                Thread.Sleep(600); // give it a moment
                poolThreads = AdvancedThreadPoolDetector.FindAdvancedThreadPools(
                    targetProcess,
                    alertableOnly: false,
                    robloxHeuristics: true,
                    verbose: false
                );

                if (poolThreads.Count == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] No thread pools found! Falling back to Burlan...");
                    Console.ResetColor();
                    InjectViaBurlan(dllPath);
                    return;
                }
            }

            // Step 2: Select best thread
            Console.WriteLine("\n[STEP 2/4] Selecting best thread...");
            Thread.Sleep(new Random().Next(200, 700));

            uint? bestThread = AdvancedThreadPoolDetector.SelectBestThread(poolThreads, targetProcess);
            if (!bestThread.HasValue)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Failed to select thread!");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[+] Selected thread: {bestThread.Value}");
            Console.ResetColor();

            // Step 3: Allocate and write DLL
            Console.WriteLine("\n[STEP 3/4] Allocating memory and writing DLL...");
            Thread.Sleep(new Random().Next(500, 1100));

            IntPtr remoteBase = StealthAlloc((uint)imageSize);
            if (remoteBase == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Memory allocation failed!");
                Console.ResetColor();
                return;
            }

            Console.WriteLine($"[+] Allocated at: 0x{remoteBase:X}");

            if (!StealthWrite(remoteBase, dllBytes))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Write failed!");
                Console.ResetColor();
                return;
            }

            Console.WriteLine("[+] DLL written successfully");

            IntPtr entryPoint = remoteBase + entryPointRVA;
            Console.WriteLine($"[+] Entry Point: 0x{entryPoint:X}");

            // Step 4: Queue APC
            Console.WriteLine("\n[STEP 4/4] Queuing APC to thread pool...");
            Thread.Sleep(new Random().Next(400, 900));

            IntPtr hThread = OpenThread(0x001F03FF, false, bestThread.Value);
            if (hThread == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Failed to open thread! Error: {Marshal.GetLastWin32Error()}");
                Console.ResetColor();
                return;
            }

            int status = NtQueueApcThread(hThread, entryPoint, remoteBase, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(hThread);

            if (status == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n╔═══════════════════════════════════════════════════╗");
                Console.WriteLine("║ ✅ INJECTION SUCCESSFUL! ✅ ║");
                Console.WriteLine("╚═══════════════════════════════════════════════════╝");
                Console.WriteLine();
                Console.WriteLine($"[✓] Method: Thread Pool APC (Xeno/Wave style)");
                Console.WriteLine($"[✓] Target Thread: {bestThread.Value}");
                Console.WriteLine($"[✓] DLL Base: 0x{remoteBase:X}");
                Console.WriteLine($"[✓] Entry Point: 0x{entryPoint:X}");
                Console.WriteLine($"[✓] Detection Window: 5s - 5min");
                Console.WriteLine($"[✓] Lifespan: Weeks - Months");
                Console.WriteLine();
                Console.WriteLine("[GARCEA]: BOSS, MERGE CA LA XENO!");
                Console.WriteLine("[GARCEA]: Thread pool APC - undetectable!");
                Console.WriteLine("[GARCEA]: Anticheatu nu ne vede!");
                Console.ResetColor();

                // ───────────────────────────────────────────────
                // Xeno.dll auto-detection + lua kiddie menu
                // ───────────────────────────────────────────────
                if (Path.GetFileName(dllPath).Equals("Xeno.dll", StringComparison.OrdinalIgnoreCase))
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine("\n╔════════════════════════════════════╗");
                    Console.WriteLine("║     XENO DETECTED – LUA TIME 💀    ║");
                    Console.WriteLine("╚════════════════════════════════════╝");
                    Console.ResetColor();

                    Console.WriteLine("[+] Type lua scripts below (one per line)");
                    Console.WriteLine("[+] Type 'exit' or 'back' to return\n");

                    while (true)
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.Write("lua> ");
                        Console.ResetColor();

                        string script = Console.ReadLine()?.Trim();
                        if (string.IsNullOrEmpty(script)) continue;

                        if (script.ToLower() == "exit" || script.ToLower() == "back" || script.ToLower() == "quit")
                        {
                            Console.WriteLine("[+] Closing Xeno lua console...");
                            break;
                        }

                        // Forward to injected Xeno via pipe
                        SendPipeCommand($"EXEC:{script}");

                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[SENT] {script}");
                        Console.ResetColor();
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] NtQueueApcThread failed! NTSTATUS: 0x{status:X}");
                Console.ResetColor();

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[!] Falling back to thread hijacking...");
                Console.ResetColor();

                InjectViaBurlan(dllPath);
            }
        }

        // ═══════════════════════════════════════════════════════
        // METHOD 2: BURLAN (THREAD HIJACKING) ★★★★☆
        // ═══════════════════════════════════════════════════════

        static void InjectViaBurlan(string dllPath)
        {
            Console.WriteLine("\n[GARCEA]: Boss, folosim Burlan (thread hijacking)!");
            Console.WriteLine("[GARCEA]: Metoda clasica, merge sigur!\n");

            bool success = RoabaBurlan.InjectBurlan(processHandle, targetProcess, dllPath);

            if (success)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[GARCEA]: ✓ Burlan injection successful boss!");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[GARCEA]: ✗ Burlan failed boss!");
                Console.ResetColor();
            }
        }

        // ═══════════════════════════════════════════════════════
        // METHOD 3: SIMPLE (CREATEREMOTETHREAD) ★★☆☆☆
        // ═══════════════════════════════════════════════════════

        static void InjectSimple(string dllPath)
        {
            Console.WriteLine("\n[GARCEA]: Boss, folosim metoda simpla (CreateRemoteThread)");
            Console.WriteLine("[GARCEA]: ATENTIE: Detectat rapid de anticheat!\n");

            byte[] dllBytes = File.ReadAllBytes(dllPath);

            if (!ValidatePE(dllBytes, out int peOffset, out int entryPointRVA, out int imageSize))
            {
                Console.WriteLine("[-] Invalid PE!");
                return;
            }

            Console.WriteLine($"[+] Allocating {imageSize} bytes...");
            IntPtr remoteBase = StealthAlloc((uint)imageSize);

            if (remoteBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Allocation failed!");
                return;
            }

            Console.WriteLine($"[+] Writing DLL to 0x{remoteBase:X}...");
            if (!StealthWrite(remoteBase, dllBytes))
            {
                Console.WriteLine("[-] Write failed!");
                return;
            }

            IntPtr entryPoint = remoteBase + entryPointRVA;
            Console.WriteLine($"[+] Entry point: 0x{entryPoint:X}");

            Console.WriteLine("[+] Creating remote thread...");
            IntPtr hThread = CreateRemoteThread(
                processHandle,
                IntPtr.Zero,
                0,
                entryPoint,
                remoteBase,
                0,
                out uint threadId
            );

            if (hThread != IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[✓] Thread created! ID: {threadId}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[WARNING] CreateRemoteThread is EASILY DETECTED!");
                Console.WriteLine("[WARNING] Expected ban time: < 30 seconds");
                Console.WriteLine("[WARNING] Use Thread Pool APC for stealth!");
                Console.ResetColor();
                CloseHandle(hThread);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] CreateRemoteThread failed!");
                Console.WriteLine($"[-] Error: {Marshal.GetLastWin32Error()}");
                Console.ResetColor();
            }
        }

        // ═══════════════════════════════════════════════════════
        // METHOD 4: DEBUG MODE (VERBOSE OUTPUT)
        // ═══════════════════════════════════════════════════════

        static void InjectDebug(string dllPath)
        {
            Console.WriteLine("\n╔═══════════════════════════════════════════════════╗");
            Console.WriteLine("║             DEBUG MODE - VERBOSE                  ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════╝\n");

            byte[] dllBytes = File.ReadAllBytes(dllPath);
            Console.WriteLine($"[DEBUG] DLL Size: {dllBytes.Length} bytes");

            // Check MZ signature
            if (dllBytes[0] != 0x4D || dllBytes[1] != 0x5A)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[DEBUG] ✗ Not a valid PE file (missing MZ signature)");
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[DEBUG] ✓ Valid MZ signature");
            Console.ResetColor();

            // Check PE offset
            int peOffset = BitConverter.ToInt32(dllBytes, 0x3C);
            Console.WriteLine($"[DEBUG] PE Offset: 0x{peOffset:X}");

            if (peOffset < 0 || peOffset > dllBytes.Length - 4)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[DEBUG] ✗ Invalid PE offset");
                Console.ResetColor();
                return;
            }

            // Check PE signature
            if (dllBytes[peOffset] != 0x50 || dllBytes[peOffset + 1] != 0x45)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[DEBUG] ✗ Invalid PE signature");
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[DEBUG] ✓ Valid PE signature");
            Console.ResetColor();

            // Get headers
            int entryPointRVA = BitConverter.ToInt32(dllBytes, peOffset + 0x28);
            int imageSize = BitConverter.ToInt32(dllBytes, peOffset + 0x50);
            short numberOfSections = BitConverter.ToInt16(dllBytes, peOffset + 0x06);

            Console.WriteLine($"[DEBUG] Entry Point RVA: 0x{entryPointRVA:X}");
            Console.WriteLine($"[DEBUG] Image Size: {imageSize} bytes");
            Console.WriteLine($"[DEBUG] Number of Sections: {numberOfSections}");

            // Allocate memory
            Console.WriteLine("\n[DEBUG] Allocating memory...");
            IntPtr remoteBase = StealthAlloc((uint)imageSize);

            if (remoteBase == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[DEBUG] ✗ Allocation failed!");
                Console.WriteLine($"[DEBUG] Error code: {Marshal.GetLastWin32Error()}");
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[DEBUG] ✓ Allocated at: 0x{remoteBase:X}");
            Console.ResetColor();

            // Write DLL
            Console.WriteLine("\n[DEBUG] Writing DLL to memory...");
            if (!StealthWrite(remoteBase, dllBytes))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[DEBUG] ✗ Write failed!");
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[DEBUG] ✓ DLL written successfully");
            Console.ResetColor();

            // Calculate entry point
            IntPtr entryPoint = remoteBase + entryPointRVA;
            Console.WriteLine($"\n[DEBUG] Entry Point Address: 0x{entryPoint:X}");

            // Try multiple methods
            Console.WriteLine("\n[DEBUG] Trying injection methods...\n");

            // Method 1: NtCreateThreadEx
            Console.WriteLine("[DEBUG] [1/3] Trying NtCreateThreadEx...");
            IntPtr hThread = AntiByfronUltra.CreateStealthThread(processHandle, entryPoint, remoteBase);

            if (hThread != IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[DEBUG] ✓ NtCreateThreadEx worked! Handle: 0x{hThread:X}");
                Console.ResetColor();
                CloseHandle(hThread);
                return;
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[DEBUG] ✗ NtCreateThreadEx failed (error: {Marshal.GetLastWin32Error()})");
            Console.ResetColor();

            // Method 2: CreateRemoteThread
            Console.WriteLine("\n[DEBUG] [2/3] Trying CreateRemoteThread...");
            hThread = CreateRemoteThread(
                processHandle,
                IntPtr.Zero,
                0,
                entryPoint,
                remoteBase,
                0,
                out uint threadId
            );

            if (hThread != IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[DEBUG] ✓ CreateRemoteThread worked! Thread ID: {threadId}");
                Console.ResetColor();
                CloseHandle(hThread);
                return;
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[DEBUG] ✗ CreateRemoteThread failed (error: {Marshal.GetLastWin32Error()})");
            Console.ResetColor();

            // Method 3: Thread Pool APC
            Console.WriteLine("\n[DEBUG] [3/3] Trying Thread Pool APC...");
            List<uint> pools = AdvancedThreadPoolDetector.FindAdvancedThreadPools(
                targetProcess,
                alertableOnly: false,
                robloxHeuristics: false,
                verbose: true
            );

            if (pools.Count > 0)
            {
                uint tid = pools[0];
                Console.WriteLine($"[DEBUG] Using thread: {tid}");

                IntPtr hPoolThread = OpenThread(0x001F03FF, false, tid);
                if (hPoolThread != IntPtr.Zero)
                {
                    int status = NtQueueApcThread(hPoolThread, entryPoint, remoteBase, IntPtr.Zero, IntPtr.Zero);
                    CloseHandle(hPoolThread);

                    if (status == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[DEBUG] ✓ Thread Pool APC worked!");
                        Console.ResetColor();
                        return;
                    }
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[DEBUG] ✗ NtQueueApcThread failed (NTSTATUS: 0x{status:X})");
                    Console.ResetColor();
                }
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[DEBUG] ✗✗✗ ALL METHODS FAILED!");
            Console.WriteLine("[DEBUG] Possible causes:");
            Console.WriteLine("  - Process has strong protections");
            Console.WriteLine("  - DLL is incompatible");
            Console.WriteLine("  - Insufficient privileges");
            Console.WriteLine("  - Anti-cheat is blocking");
            Console.ResetColor();
        }

        // ═══════════════════════════════════════════════════════
        // HELPER: VALIDATE PE
        // ═══════════════════════════════════════════════════════

        static bool ValidatePE(byte[] dllBytes, out int peOffset, out int entryPointRVA, out int imageSize)
        {
            peOffset = 0;
            entryPointRVA = 0;
            imageSize = 0;

            if (dllBytes.Length < 64)
                return false;

            // Check MZ
            if (dllBytes[0] != 0x4D || dllBytes[1] != 0x5A)
                return false;

            // Get PE offset
            peOffset = BitConverter.ToInt32(dllBytes, 0x3C);
            if (peOffset < 0 || peOffset > dllBytes.Length - 0x50)
                return false;

            // Check PE
            if (dllBytes[peOffset] != 0x50 || dllBytes[peOffset + 1] != 0x45)
                return false;

            // Get entry point and image size
            entryPointRVA = BitConverter.ToInt32(dllBytes, peOffset + 0x28);
            imageSize = BitConverter.ToInt32(dllBytes, peOffset + 0x50);

            return true;
        }

        // ═══════════════════════════════════════════════════════
        // P/INVOKE
        // ═══════════════════════════════════════════════════════

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId
        );

        [DllImport("ntdll.dll")]
        static extern int NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        static void AdvancedMode()
        {
            Console.WriteLine("\n╔═══════════════════════════════════════╗");
            Console.WriteLine("║ ⚡ ROABA TURBAT MODE ⚡ ║");
            Console.WriteLine("║ (Tehnici de la Axon si Synapse) ║");
            Console.WriteLine("╚═══════════════════════════════════════╝");
            Console.WriteLine("\n[1] Unprotect Function");
            Console.WriteLine("[2] Advanced pattern scan cu offset");
            Console.WriteLine("[3] Memory region info");
            Console.WriteLine("[4] Multi-scan pattern");
            Console.Write("\nAlege: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1": UnprotectFunctionMenu(); break;
                case "2": AdvancedPatternMenu(); break;
                case "3": MemoryRegionInfo(); break;
                case "4": MultiScanPattern(); break;
            }
        }

        static void UnprotectFunctionMenu()
        {
            try
            {
                Console.Write("\n📍 Function address (hex): ");
                IntPtr addr = (IntPtr)Convert.ToInt64(Console.ReadLine(), 16);
                IntPtr unprotected = RoabaUnprotect.UnprotectFunction(processHandle, addr);

                if (unprotected != addr)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] Unprotected copy la: 0x{unprotected.ToString("X")}");
                    Console.WriteLine("[+] Acum poti chema functia fara probleme!");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                AxleSqueaking($"Unprotect failed: {ex.Message}");
            }
        }

        static void AdvancedPatternMenu()
        {
            try
            {
                Console.WriteLine("\n🎯 Advanced Pattern Scan");
                Console.WriteLine("Example: 48 8B 0D ?? ?? ?? ?? (mov rcx, [rip+offset])");
                Console.Write("\nPattern: ");
                string pattern = Console.ReadLine();
                Console.Write("Return offset (pt RIP-relative, de obicei 3): ");
                string offsetInput = Console.ReadLine();
                int offset = string.IsNullOrEmpty(offsetInput) ? 0 : int.Parse(offsetInput);

                IntPtr result = RoabaAdvancedScan.ScanWithOffset(processHandle, targetProcess, pattern, offset);

                if (result != IntPtr.Zero)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] Gasit! Address: 0x{result.ToString("X")}");
                    Console.ResetColor();
                    Console.WriteLine("\n[+] Bytes din jur:");

                    byte[] context = new byte[32];
                    ReadProcessMemory(processHandle, result, context, 32, out _);

                    for (int i = 0; i < 32; i++)
                    {
                        if (i % 16 == 0)
                            Console.Write($"\n0x{(result.ToInt64() + i):X8}: ");
                        Console.Write($"{context[i]:X2} ");
                    }
                    Console.WriteLine("\n");
                }
                else
                {
                    Console.WriteLine("[-] Pattern nu a fost gasit");
                }
            }
            catch (Exception ex)
            {
                AxleSqueaking($"Scan failed: {ex.Message}");
            }
        }

        static void MemoryRegionInfo()
        {
            Console.WriteLine("Start Address          Size (KB)   State     Protection   Type");
            Console.WriteLine("───────────────────────────────────────────────────────────────────────────────");

            IntPtr address = targetProcess.MainModule.BaseAddress;
            long endAddress = address.ToInt64() + targetProcess.MainModule.ModuleMemorySize;

            while (address.ToInt64() < endAddress)
            {
                if (VirtualQueryEx(processHandle, address, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
                    break;

                string state = mbi.State switch
                {
                    0x1000 => "Commit ",
                    0x2000 => "Reserve",
                    0x10000 => "Free   ",
                    _ => "Unknown"
                };

                string protect = GetProtectionString(mbi.Protect);

                string type = mbi.Type switch
                {
                    0x1000000 => "Image  ",
                    0x20000 => "Mapped ",
                    0x200000 => "Private",
                    _ => "Unknown"
                };

                long sizeKB = mbi.RegionSize.ToInt64() / 1024;

                Console.WriteLine($"0x{mbi.BaseAddress.ToString("X16")}  {sizeKB.ToString().PadLeft(8)} KB   {state}   {protect.PadRight(10)}   {type}");

                address = new IntPtr(address.ToInt64() + mbi.RegionSize.ToInt64());
            }

            Console.WriteLine("\n[+] Done scanning regions");
        }

        static string GetProtectionString(uint protect)
        {
            string result = "";

            if ((protect & 0x01) != 0) result += "N/A";
            if ((protect & 0x02) != 0) result += "R";
            if ((protect & 0x04) != 0) result += "RW";
            if ((protect & 0x08) != 0) result += "WC";
            if ((protect & 0x10) != 0) result += "X";
            if ((protect & 0x20) != 0) result += "RX";
            if ((protect & 0x40) != 0) result += "RWX";
            if ((protect & 0x80) != 0) result += "WXC";

            if ((protect & 0x100) != 0) result += " (Guard)";
            if ((protect & 0x200) != 0) result += " (NOCACHE)";

            return string.IsNullOrEmpty(result) ? "???" : result;
        }

        static void MultiScanPattern()
        {
            try
            {
                Console.Write("\nPattern (hex cu wildcards): ");
                string pattern = Console.ReadLine();
                Console.Write("Max results (default 10): ");
                string maxInput = Console.ReadLine();
                int maxResults = string.IsNullOrEmpty(maxInput) ? 10 : int.Parse(maxInput);

                Console.WriteLine($"\n[+] Scanam pentru pattern: {pattern}");
                Console.WriteLine($"[+] Max {maxResults} rezultate\n");

                string[] patternParts = pattern.Split(' ');
                byte?[] patternBytes = new byte?[patternParts.Length];

                for (int i = 0; i < patternParts.Length; i++)
                {
                    if (patternParts[i] == "??" || patternParts[i] == "?")
                        patternBytes[i] = null;
                    else
                        patternBytes[i] = Convert.ToByte(patternParts[i], 16);
                }

                List<IntPtr> results = new List<IntPtr>();
                IntPtr baseAddr = targetProcess.MainModule.BaseAddress;
                int moduleSize = targetProcess.MainModule.ModuleMemorySize;
                int chunkSize = 4096;
                byte[] buffer = new byte[chunkSize];

                for (long offset = 0; offset < moduleSize && results.Count < maxResults; offset += chunkSize - patternBytes.Length)
                {
                    IntPtr currentAddress = baseAddr + (int)offset;
                    ReadProcessMemory(processHandle, currentAddress, buffer, chunkSize, out int bytesRead);

                    for (int i = 0; i < bytesRead - patternBytes.Length; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < patternBytes.Length; j++)
                        {
                            if (patternBytes[j].HasValue && buffer[i + j] != patternBytes[j].Value)
                            {
                                match = false;
                                break;
                            }
                        }

                        if (match)
                        {
                            results.Add(currentAddress + i);
                            if (results.Count >= maxResults) break;
                        }
                    }
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Gasit {results.Count} rezultate!\n");
                Console.ResetColor();

                for (int i = 0; i < results.Count; i++)
                    Console.WriteLine($" [{i}] 0x{results[i].ToString("X")}");
            }
            catch (Exception ex)
            {
                AxleSqueaking($"Multi-scan failed: {ex.Message}");
            }
        }

        static void ReadMemory()
        {
            try
            {
                Console.Write("\n📍 Adresa (hex): ");
                IntPtr address = (IntPtr)Convert.ToInt64(Console.ReadLine(), 16);
                Console.Write("📏 Cati bytes vr sa citesti (default 64): ");
                string sizeInput = Console.ReadLine();
                int size = string.IsNullOrEmpty(sizeInput) ? 64 : int.Parse(sizeInput);

                Console.WriteLine($"\n[+] Bagam roaba la 0x{address.ToString("X")}...");
                Thread.Sleep(200);

                byte[] buffer = new byte[size];
                bool success = ReadProcessMemory(processHandle, address, buffer, size, out int bytesRead);

                if (!success || bytesRead == 0)
                {
                    LoadTooHeavy($"E roaba prea grasa sa intre la 0x{address.ToString("X")}");
                    return;
                }

                Console.WriteLine($"[+] Am bagat {bytesRead} bytes in roaba\n");
                DisplayHexDump(address, buffer, bytesRead);
            }
            catch (Exception ex)
            {
                AxleSqueaking($"Ce ai mai facut prost: {ex.Message}");
            }
        }

        static void WriteMemory()
        {
            try
            {
                Console.Write("\n📍 Adresa (hex): ");
                IntPtr address = (IntPtr)Convert.ToInt64(Console.ReadLine(), 16);

                Console.WriteLine("\n📝 Ce tip de valoare vr sa mai scrii:");
                Console.WriteLine("[1] Integer (4 bytes)");
                Console.WriteLine("[2] Float (4 bytes)");
                Console.WriteLine("[3] Double (8 bytes)");
                Console.WriteLine("[4] Bytes (hex) / Roaba.dll");
                Console.Write("zi: ");

                string typeChoice = Console.ReadLine();
                byte[] dataToWrite = null;

                switch (typeChoice)
                {
                    case "1":
                        Console.Write("Valoare (integer): ");
                        int intValue = int.Parse(Console.ReadLine());
                        dataToWrite = BitConverter.GetBytes(intValue);
                        break;

                    case "2":
                        Console.Write("Valoare (float): ");
                        float floatValue = float.Parse(Console.ReadLine());
                        dataToWrite = BitConverter.GetBytes(floatValue);
                        break;

                    case "3":
                        Console.Write("Valoare (double): ");
                        double doubleValue = double.Parse(Console.ReadLine());
                        dataToWrite = BitConverter.GetBytes(doubleValue);
                        break;

                    case "4":
                        Console.Write("Bytes (hex, ex. 90 90 90) sau ENTER pentru Roaba.dll: ");
                        string hexInput = Console.ReadLine();

                        if (string.IsNullOrEmpty(hexInput))
                        {
                            string dllPath = "Roaba.dll";
                            if (!System.IO.File.Exists(dllPath))
                            {
                                AxleSqueaking("Roaba.dll nu exista boss (pune-o langa .exe)");
                                return;
                            }

                            Console.WriteLine("[+] Incarc Roaba.dll in roaba...");
                            dataToWrite = System.IO.File.ReadAllBytes(dllPath);

                            Console.ForegroundColor = ConsoleColor.Magenta;
                            Console.WriteLine($"[+] Roaba.dll loaded! {dataToWrite.Length} bytes");
                            Console.WriteLine("[+] META: Roaba bagata in roaba");
                            Console.ResetColor();
                        }
                        else
                        {
                            string[] hexBytes = hexInput.Split(' ');
                            dataToWrite = new byte[hexBytes.Length];
                            for (int i = 0; i < hexBytes.Length; i++)
                                dataToWrite[i] = Convert.ToByte(hexBytes[i], 16);
                        }
                        break;

                    default:
                        AxleSqueaking("Tip invalid");
                        return;
                }

                Console.WriteLine($"\n[+] Bagam payloadu in roaba...");
                Thread.Sleep(200);
                Console.WriteLine($"[+] Bagam roaba la 0x{address.ToString("X")}...");
                Thread.Sleep(200);

                uint oldProtect;
                bool protectChanged = VirtualProtectEx(processHandle, address, (UIntPtr)dataToWrite.Length, PAGE_EXECUTE_READWRITE, out oldProtect);

                if (!protectChanged)
                    AxleSqueaking("Nu pot sa schimb protectia memoriei");

                uint status = NtWriteVirtualMemory(processHandle, address, dataToWrite, (uint)dataToWrite.Length, out uint bytesWritten);
                bool success = status == 0;

                if (protectChanged)
                {
                    uint temp;
                    VirtualProtectEx(processHandle, address, (UIntPtr)dataToWrite.Length, oldProtect, out temp);
                }

                if (!success || bytesWritten == 0)
                {
                    WheelFellOff($"NuUuU na mers roaba :( 0x{address.ToString("X")}");
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] IeI a mers roaba {bytesWritten} bytes! 🎉");
                Console.ResetColor();

                Console.WriteLine("\n[+] Verificam daca a mers roaba corect...");
                byte[] verifyBuffer = new byte[dataToWrite.Length];
                ReadProcessMemory(processHandle, address, verifyBuffer, verifyBuffer.Length, out int verifyRead);

                Console.Write("Scris: ");
                foreach (byte b in dataToWrite) Console.Write($"{b:X2} ");
                Console.WriteLine();

                Console.Write("Verificat: ");
                foreach (byte b in verifyBuffer) Console.Write($"{b:X2} ");
                Console.WriteLine("\n");
            }
            catch (Exception ex)
            {
                TippedOver($"Sa taco bell roaba: {ex.Message}");
            }
        }

        static void ScanForValue()
        {
            try
            {
                Console.Write("\n🔍 Valoare sa scanezi (numar): ");
                int valueToFind = int.Parse(Console.ReadLine());

                IntPtr baseAddr = targetProcess.MainModule.BaseAddress;
                int moduleSize = targetProcess.MainModule.ModuleMemorySize;

                Console.WriteLine($"\n[+] Scanam {moduleSize} bytesi in roaba...");
                Console.WriteLine("[+] Stai putin bos 🐌");

                List<IntPtr> results = new List<IntPtr>();
                byte[] valueBytes = BitConverter.GetBytes(valueToFind);
                int chunkSize = 4096;
                byte[] buffer = new byte[chunkSize];

                for (long offset = 0; offset < moduleSize; offset += chunkSize - 3)
                {
                    IntPtr currentAddress = baseAddr + (int)offset;
                    ReadProcessMemory(processHandle, currentAddress, buffer, chunkSize, out int bytesRead);

                    for (int i = 0; i < bytesRead - 3; i++)
                    {
                        if (buffer[i] == valueBytes[0] && buffer[i + 1] == valueBytes[1] &&
                            buffer[i + 2] == valueBytes[2] && buffer[i + 3] == valueBytes[3])
                        {
                            results.Add(currentAddress + i);
                        }
                    }

                    if (offset % (moduleSize / 20) == 0)
                        Console.Write("█");
                }

                Console.WriteLine($"\n\n[+] Roaba a gasit {results.Count} rezultate!\n");

                if (results.Count > 0)
                {
                    Console.WriteLine("📍 Adrese:");
                    for (int i = 0; i < Math.Min(results.Count, 20); i++)
                        Console.WriteLine($" [0x{results[i].ToString("X")}] = {valueToFind}");

                    if (results.Count > 20)
                        Console.WriteLine($" ... si {results.Count - 20} mai multe");
                }
            }
            catch (Exception ex)
            {
                AxleSqueaking($"Ti se farama roaba ai grija: {ex.Message}");
            }
        }

        static void PatternScan()
        {
            try
            {
                Console.WriteLine("\n╔═══════════════════════════════════╗");
                Console.WriteLine("║    🎯 ROABA PATTERN SCANNER 🎯    ║");
                Console.WriteLine("╚═══════════════════════════════════╝");
                Console.WriteLine("\nPattern (hex cu wildcards, ex: 48 8B 05 ?? ?? ?? ??):");
                Console.Write("Pattern: ");

                string patternInput = Console.ReadLine();

                if (string.IsNullOrEmpty(patternInput))
                {
                    AxleSqueaking("Boss trebuie sa dai un pattern");
                    return;
                }

                string[] patternParts = patternInput.Split(' ');
                byte?[] pattern = new byte?[patternParts.Length];

                for (int i = 0; i < patternParts.Length; i++)
                {
                    if (patternParts[i] == "??" || patternParts[i] == "?")
                        pattern[i] = null;
                    else
                        pattern[i] = Convert.ToByte(patternParts[i], 16);
                }

                Console.WriteLine($"\n[+] Pattern: {patternInput}");
                Console.WriteLine($"[+] Lungime: {pattern.Length} bytes");
                Console.WriteLine($"[+] Wildcards: {pattern.Count(p => p == null)}");

                IntPtr baseAddr = targetProcess.MainModule.BaseAddress;
                int moduleSize = targetProcess.MainModule.ModuleMemorySize;

                Console.WriteLine($"\n[+] Scanam {moduleSize} bytes...");
                Console.WriteLine("[+] Roaba e pe drum, stai putin bos 🐌\n");

                List<IntPtr> results = new List<IntPtr>();
                int chunkSize = 4096;
                byte[] buffer = new byte[chunkSize];
                int scannedBytes = 0;
                int lastProgress = 0;

                for (long offset = 0; offset < moduleSize; offset += chunkSize - pattern.Length)
                {
                    IntPtr currentAddress = baseAddr + (int)offset;
                    ReadProcessMemory(processHandle, currentAddress, buffer, chunkSize, out int bytesRead);

                    for (int i = 0; i < bytesRead - pattern.Length; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < pattern.Length; j++)
                        {
                            if (pattern[j].HasValue && buffer[i + j] != pattern[j].Value)
                            {
                                match = false;
                                break;
                            }
                        }
                        if (match) results.Add(currentAddress + i);
                    }

                    scannedBytes += bytesRead;
                    int progress = (int)((scannedBytes / (float)moduleSize) * 100);

                    if (progress >= lastProgress + 5)
                    {
                        Console.Write($"[{progress}%] ");
                        lastProgress = progress;
                    }
                }

                Console.WriteLine("\n");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Roaba a gasit {results.Count} pattern matches! 🎉");
                Console.ResetColor();

                if (results.Count > 0)
                {
                    Console.WriteLine("\n📍 Adrese gasite:");
                    for (int i = 0; i < Math.Min(results.Count, 10); i++)
                    {
                        IntPtr addr = results[i];
                        Console.WriteLine($"\n [{i}] 0x{addr.ToString("X")}");

                        byte[] foundBytes = new byte[pattern.Length];
                        ReadProcessMemory(processHandle, addr, foundBytes, pattern.Length, out _);

                        Console.Write(" Bytes: ");
                        for (int j = 0; j < foundBytes.Length; j++)
                        {
                            if (pattern[j].HasValue)
                            {
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Console.Write($"{foundBytes[j]:X2} ");
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.Write($"{foundBytes[j]:X2} ");
                                Console.ResetColor();
                            }
                        }
                        Console.WriteLine();
                    }

                    if (results.Count > 10)
                        Console.WriteLine($"\n ... si inca {results.Count - 10} rezultate");

                    Console.Write("\n\n📝 Vrei sa citesti/scrii la vreuna? (numarul sau ENTER): ");
                    string choice = Console.ReadLine();

                    if (!string.IsNullOrEmpty(choice) && int.TryParse(choice, out int index) && index >= 0 && index < results.Count)
                    {
                        IntPtr selectedAddr = results[index];
                        Console.WriteLine($"\n[+] Adresa selectata: 0x{selectedAddr.ToString("X")}");
                        Console.WriteLine("\n[1] Citeste mai multi bytes");
                        Console.WriteLine("[2] Scrie aici");
                        Console.Write("Alege: ");

                        string action = Console.ReadLine();

                        if (action == "1")
                        {
                            Console.Write("Cati bytes? ");
                            int size = int.Parse(Console.ReadLine());
                            byte[] data = new byte[size];
                            ReadProcessMemory(processHandle, selectedAddr, data, size, out _);
                            DisplayHexDump(selectedAddr, data, size);
                        }
                        else if (action == "2")
                        {
                            Console.Write("Scrie bytes (hex, ex: 90 90 90): ");
                            string[] hexBytes = Console.ReadLine().Split(' ');
                            byte[] dataToWrite = new byte[hexBytes.Length];

                            for (int i = 0; i < hexBytes.Length; i++)
                                dataToWrite[i] = Convert.ToByte(hexBytes[i], 16);

                            uint oldProtect;
                            VirtualProtectEx(processHandle, selectedAddr, (UIntPtr)dataToWrite.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
                            uint status = NtWriteVirtualMemory(processHandle, selectedAddr, dataToWrite, (uint)dataToWrite.Length, out uint written);
                            uint temp;
                            VirtualProtectEx(processHandle, selectedAddr, (UIntPtr)dataToWrite.Length, oldProtect, out temp);

                            if (status == 0)
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"[+] Scris {written} bytes! 🎉");
                                Console.ResetColor();
                            }
                            else
                            {
                                WheelFellOff("Nu a mers scrierea");
                            }
                        }
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Roaba nu a gasit nimic :(");
                    Console.WriteLine(" (Verifica pattern-ul sau incearca alt proces)");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                TippedOver($"Pattern scan a dat cu roaba peste cap: {ex.Message}");
            }
        }

        static void DisplayHexDump(IntPtr startAddress, byte[] buffer, int bytesRead)
        {
            Console.WriteLine("📦 In roaba:\n");

            for (int i = 0; i < bytesRead; i += 16)
            {
                Console.Write($"0x{(startAddress.ToInt64() + i):X8} ");

                for (int j = 0; j < 16 && i + j < bytesRead; j++)
                    Console.Write($"{buffer[i + j]:X2} ");

                for (int j = bytesRead - i; j < 16; j++)
                    Console.Write("   ");

                Console.Write(" | ");

                for (int j = 0; j < 16 && i + j < bytesRead; j++)
                {
                    char c = (char)buffer[i + j];
                    Console.Write(char.IsControl(c) ? '.' : c);
                }

                Console.WriteLine();
            }
        }

        static void ShowSplashScreen()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("╔═════════════════════════════════════════╗");
            Console.WriteLine("║                                         ║");
            Console.WriteLine("║             🛞 ROABA X 🛞               ║");
            Console.WriteLine("║         (garantat tigan proof)          ║");
            Console.WriteLine("║      \"o roata, hackuri infinite\"        ║");
            Console.WriteLine("║              LOVE HIRO                  ║");
            Console.WriteLine("║   Powered by magie si o roata proasta   ║");
            Console.WriteLine("║(si un ax prost ca sa fie treaba treaba) ║");
            Console.WriteLine("║            BAGA VITEZA BOS              ║");
            Console.WriteLine("║    versuiunea: 3.Roaba pictata pro      ║");
            Console.WriteLine("║         florin salam on top             ║");
            Console.WriteLine("╚═════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            Console.Write("[+] Loading wheel... ");
            for (int i = 0; i <= 100; i += 10)
            {
                Console.Write("█");
                Thread.Sleep(50);
            }
            Console.WriteLine(" 100%");

            Console.Write("[+] Stai putin bos verific roaba... ");
            Thread.Sleep(300);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[WOBBLING]");
            Console.ResetColor();

            Console.WriteLine("[+] Bagam ulei de motor la roti... ");
            Thread.Sleep(300);

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("[+] ROABA TURBO MOD ACTIVAT");
            Console.ResetColor();
            Thread.Sleep(300);

            Console.WriteLine("[+] Ok gata 🪣\n");
            Thread.Sleep(500);
        }

        static void WheelFellOff(string reason)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[-] Tia cazut roata prostule");
            Console.WriteLine($" (O dat crash: {reason})");
            Console.ResetColor();
        }

        static void LoadTooHeavy(string reason)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[-] TIAM ZIS IO CA STRICI ROABA");
            Console.WriteLine($" (na eroare: {reason})");
            Console.ResetColor();
        }

        static void AxleSqueaking(string warning)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n[!] Mai baga ulei de motor");
            Console.WriteLine($" (esti bun: {warning})");
            Console.ResetColor();
        }

        static void TippedOver(string error)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n[X] A CAZUT ROABA NUuUuUuU");
            Console.WriteLine($" (combo fatal, eroare: {error})");
            Console.ResetColor();
        }
    };
};
