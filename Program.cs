using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Roaba_Matii
{
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
                        Array.Fill(buffer, backgroundASCIICode);
                        Array.Fill(zBuffer, 0f);

                        RenderCube(6, 0, "ROABA", 0);

                        int currentX = Console.WindowWidth - width - 2;

                        for (int y = 0; y < height; y++)
                        {
                            Console.SetCursorPosition(currentX, startY + y);

                            StringBuilder line = new StringBuilder(width);
                            for (int x = 0; x < width; x++)
                            {
                                line.Append(buffer[x + y * width]);
                            }
                            Console.Write(line.ToString());
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
            if (cubeThread != null)
            {
                cubeThread.Join(1000);
            }

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

        private static void RenderCube(float cubeWidth, float horizontalOffset, string text, int yOffset)
        {
            for (float cubeX = -cubeWidth; cubeX < cubeWidth; cubeX += incrementSpeed)
            {
                for (float cubeY = -cubeWidth; cubeY < cubeWidth; cubeY += incrementSpeed)
                {
                    DrawFace(cubeX, cubeY, -cubeWidth, frontChar, horizontalOffset, yOffset);
                    DrawFace(cubeWidth, cubeY, cubeX, rightChar, horizontalOffset, yOffset);
                    DrawFace(-cubeWidth, cubeY, -cubeX, leftChar, horizontalOffset, yOffset);
                    DrawFace(-cubeX, cubeY, cubeWidth, backChar, horizontalOffset, yOffset);
                    DrawFace(cubeX, -cubeWidth, -cubeY, bottomChar, horizontalOffset, yOffset);
                    DrawFace(cubeX, cubeWidth, cubeY, topChar, horizontalOffset, yOffset);
                }
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

                float ooz = 1 / z;
                ooz += 0.001f;

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

        private static float CalculateX(float i, float j, float k)
        {
            return j * (float)Math.Sin(A) * (float)Math.Sin(B) * (float)Math.Cos(C) -
                   k * (float)Math.Cos(A) * (float)Math.Sin(B) * (float)Math.Cos(C) +
                   j * (float)Math.Cos(A) * (float)Math.Sin(C) +
                   k * (float)Math.Sin(A) * (float)Math.Sin(C) +
                   i * (float)Math.Cos(B) * (float)Math.Cos(C);
        }

        private static float CalculateY(float i, float j, float k)
        {
            return j * (float)Math.Cos(A) * (float)Math.Cos(C) +
                   k * (float)Math.Sin(A) * (float)Math.Cos(C) -
                   j * (float)Math.Sin(A) * (float)Math.Sin(B) * (float)Math.Sin(C) +
                   k * (float)Math.Cos(A) * (float)Math.Sin(B) * (float)Math.Sin(C) -
                   i * (float)Math.Cos(B) * (float)Math.Sin(C);
        }

        private static float CalculateZ(float i, float j, float k)
        {
            return k * (float)Math.Cos(A) * (float)Math.Cos(B) -
                   j * (float)Math.Sin(A) * (float)Math.Cos(B) +
                   i * (float)Math.Sin(B);
        }
    }

    // NEW: Axon-style Unprotect
    class RoabaUnprotect
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

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
                // x64 epilogue patterns
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
                // Axon pattern: jb instruction followed by security check
                if (bytes[i] == 0x72 && i + 7 < size && bytes[i + 2] == 0xA1 && bytes[i + 7] == 0x8B)
                {
                    Console.WriteLine($"    [*] Found security check at offset +0x{i:X} (Axon pattern)");
                    bytes[i] = 0xEB; // jb -> jmp
                    patchCount++;
                }

                // INT3 breakpoints
                if (bytes[i] == 0xCC)
                {
                    Console.WriteLine($"    [*] Found INT3 at offset +0x{i:X}");
                    bytes[i] = 0x90; // NOP
                    patchCount++;
                }
            }

            if (patchCount > 0)
            {
                Marshal.Copy(bytes, 0, funcAddr, size);
            }

            return patchCount;
        }
    }

    // NEW: Advanced Pattern Scanner
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

                    if (match)
                    {
                        return currentAddress + i;
                    }
                }
            }

            return IntPtr.Zero;
        }
    }

    class RoabaX
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READWRITE = 0x04;

        public static IntPtr processHandle = IntPtr.Zero;
        public static Process targetProcess = null;

        static void Main()
        {
            ShowSplashScreen();

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
                    return;
                }

                Console.WriteLine($"[+] ok bn am bagat prostia in roaba (vezi sa nu iti scape roaba) Handel: 0x{processHandle.ToString("X")}");
                Console.WriteLine($"[+] Base address: 0x{targetProcess.MainModule.BaseAddress.ToString("X")}");

                bool running = true;
                while (running)
                {
                    Console.WriteLine("\n╔═══════════════════════════════════╗");
                    Console.WriteLine("║        🛞 ROABA X MENU 🛞         ║");
                    Console.WriteLine("╚═══════════════════════════════════╝");
                    Console.WriteLine("[1] 📖 Citeste memorie");
                    Console.WriteLine("[2] ✏️  Scrie memorie");
                    Console.WriteLine("[3] 🔍 Skaneaza ca aia din star trek pt o valoare");
                    Console.WriteLine("[4] 🎯 Pattern scan (AOB ca profesionistii)");
                    Console.WriteLine("[5] ⚡ ROABA TURBO");
                    Console.WriteLine("[6] 🚪 Parkeaza roaba");
                    Console.Write("\n🔧 Choice: ");

                    string choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            ReadMemory();
                            break;
                        case "2":
                            WriteMemory();
                            break;
                        case "3":
                            ScanForValue();
                            break;
                        case "4":
                            PatternScan();
                            break;
                        case "5":
                            AdvancedMode();
                            break;
                        case "6":
                            running = false;
                            break;
                        default:
                            AxleSqueaking("Ai bagat adresa de memorie in loc de optiune?");
                            break;
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

            Console.WriteLine("\n🛞 press any key sa nu iti ia tigani roaba...");
            Console.ReadKey();
        }

        // NEW: Advanced Mode Menu
        static void AdvancedMode()
        {
            Console.WriteLine("\n╔═══════════════════════════════════════╗");
            Console.WriteLine("║      ⚡ ROABA TURBAT MODE ⚡          ║");
            Console.WriteLine("║   (Tehnici de la Axon si Synapse)     ║");
            Console.WriteLine("╚═══════════════════════════════════════╝");

            Console.WriteLine("\n[1] 🔓 Unprotect Function (Axon style)");
            Console.WriteLine("[2] 🎯 Advanced pattern scan cu offset");
            Console.WriteLine("[3] 📊 Memory region info");
            Console.WriteLine("[4] 🔍 Multi-scan pattern");
            Console.Write("\nAlege: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    UnprotectFunctionMenu();
                    break;
                case "2":
                    AdvancedPatternMenu();
                    break;
                case "3":
                    MemoryRegionInfo();
                    break;
                case "4":
                    MultiScanPattern();
                    break;
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
                Console.WriteLine("\n🎯 Advanced Pattern Scan (Axon Style)");
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
                        if (i % 16 == 0) Console.Write($"\n0x{(result.ToInt64() + i):X8}:  ");
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
            Console.WriteLine("\n📊 Memory Region Scanner");
            Console.WriteLine("[+] Analyzing process memory...\n");

            Console.WriteLine("Region          Start Address         Size        Protection");
            Console.WriteLine("────────────────────────────────────────────────────────────");

            IntPtr baseAddr = targetProcess.MainModule.BaseAddress;
            int moduleSize = targetProcess.MainModule.ModuleMemorySize;

            Console.WriteLine($"Main Module     0x{baseAddr.ToString("X").PadRight(20)} {(moduleSize / 1024).ToString().PadRight(12)} KB    RWX");

            Console.WriteLine($"\n[+] Module: {targetProcess.MainModule.ModuleName}");
            Console.WriteLine($"[+] Base: 0x{baseAddr.ToString("X")}");
            Console.WriteLine($"[+] Size: {moduleSize / 1024 / 1024} MB");
            Console.WriteLine($"[+] Entry Point: 0x{targetProcess.MainModule.EntryPointAddress.ToString("X")}");
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
                {
                    Console.WriteLine($"  [{i}] 0x{results[i].ToString("X")}");
                }
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
                            Console.WriteLine("[+] META: Roaba bagata in roaba 🛞➡️🛞");
                            Console.ResetColor();
                        }
                        else
                        {
                            string[] hexBytes = hexInput.Split(' ');
                            dataToWrite = new byte[hexBytes.Length];
                            for (int i = 0; i < hexBytes.Length; i++)
                            {
                                dataToWrite[i] = Convert.ToByte(hexBytes[i], 16);
                            }
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

                bool protectChanged = VirtualProtectEx(
                    processHandle,
                    address,
                    (UIntPtr)dataToWrite.Length,
                    PAGE_EXECUTE_READWRITE,
                    out oldProtect
                );

                if (!protectChanged)
                {
                    AxleSqueaking("Nu pot sa schimb protectia memoriei");
                }

                bool success = WriteProcessMemory(processHandle, address, dataToWrite, dataToWrite.Length, out int bytesWritten);

                if (protectChanged)
                {
                    uint temp;
                    VirtualProtectEx(
                        processHandle,
                        address,
                        (UIntPtr)dataToWrite.Length,
                        oldProtect,
                        out temp
                    );
                }

                if (!success || bytesWritten == 0)
                {
                    WheelFellOff($"NuUuU na mers roaba :(  0x{address.ToString("X")}");
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] IeI a mers roaba {bytesWritten} bytes! 🎉");
                Console.ResetColor();

                Console.WriteLine("\n[+] Verificam daca a mers roaba corect...");
                byte[] verifyBuffer = new byte[dataToWrite.Length];
                ReadProcessMemory(processHandle, address, verifyBuffer, verifyBuffer.Length, out int verifyRead);

                Console.Write("Scris: ");
                foreach (byte b in dataToWrite)
                    Console.Write($"{b:X2} ");
                Console.WriteLine();

                Console.Write("Verificat: ");
                foreach (byte b in verifyBuffer)
                    Console.Write($"{b:X2} ");
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
                        if (buffer[i] == valueBytes[0] &&
                            buffer[i + 1] == valueBytes[1] &&
                            buffer[i + 2] == valueBytes[2] &&
                            buffer[i + 3] == valueBytes[3])
                        {
                            results.Add(currentAddress + i);
                        }
                    }

                    if (offset % (moduleSize / 20) == 0)
                    {
                        Console.Write("█");
                    }
                }

                Console.WriteLine($"\n\n[+] Roaba a gasit {results.Count} rezultate!\n");

                if (results.Count > 0)
                {
                    Console.WriteLine("📍 Adrese:");
                    for (int i = 0; i < Math.Min(results.Count, 20); i++)
                    {
                        Console.WriteLine($"  [0x{results[i].ToString("X")}] = {valueToFind}");
                    }

                    if (results.Count > 20)
                    {
                        Console.WriteLine($"  ... si {results.Count - 20} mai multe");
                    }
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
                    {
                        pattern[i] = null;
                    }
                    else
                    {
                        pattern[i] = Convert.ToByte(patternParts[i], 16);
                    }
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

                        if (match)
                        {
                            results.Add(currentAddress + i);
                        }
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
                        Console.WriteLine($"\n  [{i}] 0x{addr.ToString("X")}");

                        byte[] foundBytes = new byte[pattern.Length];
                        ReadProcessMemory(processHandle, addr, foundBytes, pattern.Length, out _);

                        Console.Write("      Bytes: ");
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
                    {
                        Console.WriteLine($"\n  ... si inca {results.Count - 10} rezultate");
                    }

                    Console.Write("\n\n📝 Vrei sa citesti/scrii la vreuna? (numarul sau ENTER): ");
                    string choice = Console.ReadLine();

                    if (!string.IsNullOrEmpty(choice) && int.TryParse(choice, out int index))
                    {
                        if (index >= 0 && index < results.Count)
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
                                {
                                    dataToWrite[i] = Convert.ToByte(hexBytes[i], 16);
                                }

                                uint oldProtect;
                                VirtualProtectEx(processHandle, selectedAddr, (UIntPtr)dataToWrite.Length, PAGE_EXECUTE_READWRITE, out oldProtect);

                                bool success = WriteProcessMemory(processHandle, selectedAddr, dataToWrite, dataToWrite.Length, out int written);

                                uint temp;
                                VirtualProtectEx(processHandle, selectedAddr, (UIntPtr)dataToWrite.Length, oldProtect, out temp);

                                if (success)
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
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Roaba nu a gasit nimic :(");
                    Console.WriteLine("    (Verifica pattern-ul sau incearca alt proces)");
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
                Console.Write($"0x{(startAddress.ToInt64() + i):X8}  ");

                for (int j = 0; j < 16 && i + j < bytesRead; j++)
                {
                    Console.Write($"{buffer[i + j]:X2} ");
                }

                for (int j = bytesRead - i; j < 16; j++)
                {
                    Console.Write("   ");
                }

                Console.Write("  ");

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
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("╔═════════════════════════════════════════╗");
            Console.WriteLine("║                                         ║");
            Console.WriteLine("║            🛞 ROABA X 🛞                ║");
            Console.WriteLine("║         (garantat tigan proof)          ║");
            Console.WriteLine("║      \"o roata, hackuri infinite\"        ║");
            Console.WriteLine("║              LOVE HIRO                  ║");
            Console.WriteLine("║    Powered by magie si o roata proasta  ║");
            Console.WriteLine("║(si un ax prost ca sa fie treaba treaba) ║");
            Console.WriteLine("║            BAGA VITEZA BOS              ║");
            Console.WriteLine("║     versuiunea: 1.Roaba Pe Benzina      ║");
            Console.WriteLine("║         florin salam on top             ║");
            Console.WriteLine("╚═════════════════════════════════════════╝");
            Console.ResetColor();
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

            Console.WriteLine("[+] Bagam ulei de motor la roti... ✅");
            Thread.Sleep(300);

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("[+] Axon power mode ACTIVATED ⚡");
            Console.ResetColor();
            Thread.Sleep(300);

            Console.WriteLine("[+] Ok gata 🪣\n");
            Thread.Sleep(500);
        }

        static void WheelFellOff(string reason)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[-] Tia cazut roata prostule");
            Console.WriteLine($"    (O dat crash: {reason})");
            Console.ResetColor();
        }

        static void LoadTooHeavy(string reason)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[-] TIAM ZIS IO CA STRICI ROABA");
            Console.WriteLine($"    (na eroare: {reason})");
            Console.ResetColor();
        }

        static void AxleSqueaking(string warning)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n[!] Mai baga ulei de motor");
            Console.WriteLine($"    (esti bun: {warning})");
            Console.ResetColor();
        }

        static void TippedOver(string error)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\n[X] A CAZUT ROABA NUuUuUuU");
            Console.WriteLine($"    (combo fatal, eroare: {error})");
            Console.ResetColor();
        }
    }
}
