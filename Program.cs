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

        const int width = 40;  // Smaller for corner
        const int height = 20; // Smaller for corner
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

        // Start cube in background thread
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

                        // Render cube
                        RenderCube(6, 0, "ROABA", 0);

                        // Draw to top right corner
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
                    catch
                    {
                        // Ignore errors if console resizes
                    }
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

            // Clear cube area
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

            // Draw text in front
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
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

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

        static IntPtr processHandle = IntPtr.Zero;
        static Process targetProcess = null;

        static void Main()
        {
            ShowSplashScreen();

            try
            {
                // Select process
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
                Console.Write("SA MORI TU, " + allProcesses[index]);
                targetProcess = allProcesses[index];

                Console.WriteLine($"\n[+] stai putin bag procesu in roaba: {targetProcess.ProcessName} ...");
                Thread.Sleep(500);

                // Open with read AND write permissions
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

                // Main menu loop
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
                    Console.WriteLine("[5] 🚪 Parkeaza roaba");
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
                            // Load Roaba.dll from disk
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

                // LOCAL variable for old protect
                uint oldProtect;

                // Change protection to writable
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

                // Write the data
                bool success = WriteProcessMemory(processHandle, address, dataToWrite, dataToWrite.Length, out int bytesWritten);

                // Restore original protection
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

                // Read back to verify
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

                    // Progress indicator
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

                // Parse pattern
                string[] patternParts = patternInput.Split(' ');
                byte?[] pattern = new byte?[patternParts.Length];

                for (int i = 0; i < patternParts.Length; i++)
                {
                    if (patternParts[i] == "??" || patternParts[i] == "?")
                    {
                        pattern[i] = null; // Wildcard
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

                    // Scan this chunk for pattern
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

                    // Update progress every 5%
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

                        // Show bytes at this location
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

                    // Option to read/write at found address
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

                // Hex values
                for (int j = 0; j < 16 && i + j < bytesRead; j++)
                {
                    Console.Write($"{buffer[i + j]:X2} ");
                }

                // Padding
                for (int j = bytesRead - i; j < 16; j++)
                {
                    Console.Write("   ");
                }

                Console.Write("  ");

                // ASCII
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
            Console.WriteLine("║            🛞 ROABA X 🛞                ║");
            Console.WriteLine("║         (garantat tigan proof)          ║");
            Console.WriteLine("║      \"o roata, hackuri infinite\"        ║");
            Console.WriteLine("║              LOVE HIRO  ❤️              ║");
            Console.WriteLine("║    Powered by magie si o roata proasta  ║");
            Console.WriteLine("║(si un ax prost ca sa fie treaba treaba) ║");
            Console.WriteLine("║                                         ║");
            Console.WriteLine("║       versuiunea: 1.Roaba-RW            ║");
            Console.WriteLine("║         florin salam on top             ║");
            Console.WriteLine("╚═════════════════════════════════════════╝");
            Console.ResetColor();
            //RoabaCube.StartCube();
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
