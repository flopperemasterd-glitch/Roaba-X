#include "pch.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>

using namespace std;

// Function prototypes
DWORD WINAPI RoabaMain(LPVOID lpParam);
void ReadMemoryExample();
void WriteMemoryExample();
void ScanMemoryExample();
void ShowMenu();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, RoabaMain, hModule, 0, NULL);
    }
    return TRUE;
}

DWORD WINAPI RoabaMain(LPVOID lpParam) {
    // Setup console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONIN$", "r", stdin);

    // Splash
    system("color 0E"); // Yellow on black
    cout << "╔═════════════════════════════════════════╗" << endl;
    cout << "║                                         ║" << endl;
    cout << "║      🛞 ROABA BAGATA IN PROCES! 🛞     ║" << endl;
    cout << "║                                         ║" << endl;
    cout << "║          The roaba is inside!           ║" << endl;
    cout << "║                                         ║" << endl;
    cout << "╚═════════════════════════════════════════╝\n" << endl;

    cout << "[+] DLL loaded successfully!" << endl;
    cout << "[+] Base Address: 0x" << hex << (DWORD64)GetModuleHandle(NULL) << dec << endl;
    cout << "[+] Proces ID: " << GetCurrentProcessId() << endl;

    Sleep(1000);

    // Main loop
    bool running = true;
    while (running) {
        ShowMenu();

        int choice;
        cout << "\n🔧 Alegere: ";
        cin >> choice;
        cin.ignore();

        switch (choice) {
        case 1:
            ReadMemoryExample();
            break;
        case 2:
            WriteMemoryExample();
            break;
        case 3:
            ScanMemoryExample();
            break;
        case 4:
            cout << "\n[+] Bagam roaba in boschetsi..." << endl;
            running = false;
            break;
        default:
            cout << "[!] esti bun" << endl;
            break;
        }
    }

    // Cleanup
    Sleep(500);
    fclose(stdout);
    fclose(stdin);
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

void ShowMenu() {
    cout << "\n╔═══════════════════════════════════╗" << endl;
    cout << "║        🛞 MENIU ROABA 🛞          ║" << endl;
    cout << "╚═══════════════════════════════════╝" << endl;
    cout << "[1] ?? Read memory" << endl;
    cout << "[2] ??  Write memory" << endl;
    cout << "[3] ?? Scan memory" << endl;
    cout << "[4] ?? Unload DLL" << endl;
}

void ReadMemoryExample() {
    cout << "\n📍 Adresa (hex): 0x";
    DWORD64 address;
    cin >> hex >> address >> dec;

    cout << "📏 Bytes sa citesti (ca pe gagici :) ): ";
    int size;
    cin >> size;
    cin.ignore();

    cout << "\n[+] Citim " << size << " bytes de la 0x" << hex << address << dec << "..." << endl;

    try {
        BYTE* buffer = new BYTE[size];
        memcpy(buffer, (void*)address, size);

        cout << "\n📦 Roaba:\n" << endl;
        for (int i = 0; i < size; i += 16) {
            printf("0x%08llX  ", address + i);

            // Hex
            for (int j = 0; j < 16 && i + j < size; j++) {
                printf("%02X ", buffer[i + j]);
            }

            // Padding
            for (int j = size - i; j < 16; j++) {
                printf("   ");
            }

            cout << " ";

            // ASCII
            for (int j = 0; j < 16 && i + j < size; j++) {
                char c = buffer[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }

            cout << endl;
        }

        delete[] buffer;
        cout << "\n[+] Am terminat de citi" << endl;
    }
    catch (...) {
        cout << "[-] am dato in bara cu memoria si am si violat (nu gagici de data asta D: ) permisiunile de memorie" << endl;
    }
}

void WriteMemoryExample() {
    cout << "\n📍 Adresa (hex): 0x";
    DWORD64 address;
    cin >> hex >> address >> dec;

    cout << "\n?? Tipul de valoare:" << endl;
    cout << "[1] Integer (4 bytes)" << endl;
    cout << "[2] Float (4 bytes)" << endl;
    cout << "[3] Bytes (hex)" << endl;
    cout << "Choice: ";

    int choice;
    cin >> choice;

    try {
        DWORD oldProtect;

        switch (choice) {
        case 1: {
            cout << "Valoare (int): ";
            int value;
            cin >> value;

            VirtualProtect((LPVOID)address, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect);
            *(int*)address = value;
            VirtualProtect((LPVOID)address, sizeof(int), oldProtect, &oldProtect);

            cout << "\n[+] Scris " << value << " la 0x" << hex << address << dec << endl;
            break;
        }
        case 2: {
            cout << "Valoare (float): ";
            float value;
            cin >> value;

            VirtualProtect((LPVOID)address, sizeof(float), PAGE_EXECUTE_READWRITE, &oldProtect);
            *(float*)address = value;
            VirtualProtect((LPVOID)address, sizeof(float), oldProtect, &oldProtect);

            cout << "\n[+] Scris " << value << " la 0x" << hex << address << dec << endl;
            break;
        }
        case 3: {
            cout << "Bytesi (hex, e.g., 90 90 90): ";
            cin.ignore();
            string hexInput;
            getline(cin, hexInput);

            vector<BYTE> bytes;
            stringstream ss(hexInput);
            string byteStr;
            while (ss >> byteStr) {
                bytes.push_back((BYTE)stoi(byteStr, nullptr, 16));
            }

            VirtualProtect((LPVOID)address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((void*)address, bytes.data(), bytes.size());
            VirtualProtect((LPVOID)address, bytes.size(), oldProtect, &oldProtect);

            cout << "\n[+] Scris " << bytes.size() << " bytes la 0x" << hex << address << dec << endl;
            break;
        }
        }
    }
    catch (...) {
        cout << "[-] Am dato in bara cu memoria dinou :(" << endl;
    }
}

void ScanMemoryExample() {
    cout << "\n🔍 Valoare sa scanam (int): ";
    int valueToFind;
    cin >> valueToFind;

    cout << "\n[+] Scanare memorie..." << endl;
    cout << "[+] E roaba ruginita deci va lua cv timp! ??" << endl;

    vector<DWORD64> results;

    MEMORY_BASIC_INFORMATION mbi;
    DWORD64 address = 0;

    while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            try {
                BYTE* buffer = new BYTE[mbi.RegionSize];
                memcpy(buffer, mbi.BaseAddress, mbi.RegionSize);

                for (size_t i = 0; i < mbi.RegionSize - 3; i++) {
                    if (*(int*)(buffer + i) == valueToFind) {
                        results.push_back((DWORD64)mbi.BaseAddress + i);
                    }
                }

                delete[] buffer;
            }
            catch (...) {
                // Skip inaccessible regions
            }
        }

        address = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
    }

    cout << "\n[+] Am gasit " << results.size() << " resultate!\n" << endl;

    if (results.size() > 0) {
        cout << "📍 Adrese:" << endl;
        for (size_t i = 0; i < min(results.size(), (size_t)20); i++) {
            cout << "  [0x" << hex << results[i] << dec << "] = " << valueToFind << endl;
        }

        if (results.size() > 20) {
            cout << "  ... si " << (results.size() - 20) << " mai mult(e)" << endl;
        }
    }
}
