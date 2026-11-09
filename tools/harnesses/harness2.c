/*
 * PoC harness: llama directo a Rules_GetPassword / Rules_GetTSeed de
 * RulesLicenceManager.dll para extraer empiricamente la password/seed
 * real usada por el cifrado (en vez de seguir rastreando estaticamente
 * su inicializacion via propiedades COM).
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef int (__stdcall *Rules_GetPassword_t)(const char* partNumber, char* outBuf, int* outErr);
typedef int (__stdcall *Rules_GetTSeed_t)(const char* partNumber, char* outBuf);

static void hexdump(const unsigned char* buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main(int argc, char** argv) {
    const char* dllPath = (argc >= 2) ? argv[1] : "RulesLicenceManager.dll";
    const char* partNumber = (argc >= 3) ? argv[2] : "TWDBTFU10ES";

    printf("[*] Cargando %s ...\n", dllPath);
    HMODULE h = LoadLibraryA(dllPath);
    if (!h) { printf("[!] LoadLibrary fallo, error=%lu\n", GetLastError()); return 1; }
    printf("[+] DLL cargada en base=%p\n", (void*)h);

    Rules_GetPassword_t pGetPassword = (Rules_GetPassword_t)GetProcAddress(h, "Rules_GetPassword");
    Rules_GetTSeed_t pGetTSeed = (Rules_GetTSeed_t)GetProcAddress(h, "Rules_GetTSeed");

    printf("Rules_GetPassword = %p\n", (void*)pGetPassword);
    printf("Rules_GetTSeed    = %p\n", (void*)pGetTSeed);
    printf("Part number usado: %s\n\n", partNumber);

    if (pGetPassword) {
        unsigned char buf[512];
        memset(buf, 0xCC, sizeof(buf)); /* relleno centinela para ver cuanto escribe */
        int err = 0;
        printf("[*] Llamando Rules_GetPassword(\"%s\", buf, &err) ...\n", partNumber);
        int hr = pGetPassword(partNumber, (char*)buf, &err);
        printf("    HRESULT = 0x%08X   err=%d\n", (unsigned)hr, err);
        printf("    Como ANSI:  \"%s\"\n", (char*)buf);
        printf("    Como UTF16: \"%ls\"\n", (wchar_t*)buf);
        printf("    Hexdump (64 bytes):\n");
        hexdump(buf, 64);
    }

    if (pGetTSeed) {
        unsigned char buf[512];
        memset(buf, 0xCC, sizeof(buf));
        printf("\n[*] Llamando Rules_GetTSeed(\"%s\", buf) ...\n", partNumber);
        int hr = pGetTSeed(partNumber, (char*)buf);
        printf("    HRESULT = 0x%08X\n", (unsigned)hr);
        printf("    Como ANSI:  \"%s\"\n", (char*)buf);
        printf("    Como UTF16: \"%ls\"\n", (wchar_t*)buf);
        printf("    Hexdump (64 bytes):\n");
        hexdump(buf, 64);
    }

    printf("\n[*] Fin.\n");
    return 0;
}
