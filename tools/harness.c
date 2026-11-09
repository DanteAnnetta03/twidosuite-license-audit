/*
 * PoC harness para auditoria de seguridad: llama directamente a las
 * funciones exportadas por BrickLicenceManager.dll (sin pasar por la
 * GUI de VB6) para observar el comportamiento de Hub_OpenSession /
 * Hub_GetActiveLicenseState antes y despues de parchear la DLL.
 *
 * Uso: harness.exe <ruta_a_BrickLicenceManager.dll>
 */
#include <windows.h>
#include <stdio.h>

/* Prototipos aproximados en base al analisis estatico (cdecl, HRESULT-like return) */
typedef int (__stdcall *Hub_OpenSession_t)(void* arg1, void* arg2, void* arg3, void* arg4);
typedef int (__stdcall *Hub_CloseSession_t)(void* session);
typedef int (__stdcall *Hub_GetActiveLicenseState_t)(void* session, void* arg2, void* arg3, int* outState);
typedef int (__stdcall *Hub_GetLastErrorCode_t)(void* session);
typedef int (__cdecl   *pp_libversion_t)(char* buf, int len);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("uso: %s <BrickLicenceManager.dll>\n", argv[0]);
        return 1;
    }

    printf("[*] Cargando %s ...\n", argv[1]);
    HMODULE h = LoadLibraryA(argv[1]);
    if (!h) {
        printf("[!] LoadLibrary fallo, error=%lu\n", GetLastError());
        return 1;
    }
    printf("[+] DLL cargada en base=%p\n", (void*)h);

    Hub_GetActiveLicenseState_t pGetState =
        (Hub_GetActiveLicenseState_t)GetProcAddress(h, "Hub_GetActiveLicenseState");
    Hub_OpenSession_t pOpenSession =
        (Hub_OpenSession_t)GetProcAddress(h, "Hub_OpenSession");
    Hub_CloseSession_t pCloseSession =
        (Hub_CloseSession_t)GetProcAddress(h, "Hub_CloseSession");
    Hub_GetLastErrorCode_t pGetLastErr =
        (Hub_GetLastErrorCode_t)GetProcAddress(h, "Hub_GetLastErrorCode");

    printf("[*] Direcciones resueltas:\n");
    printf("    Hub_OpenSession          = %p\n", (void*)pOpenSession);
    printf("    Hub_GetActiveLicenseState= %p\n", (void*)pGetState);
    printf("    Hub_CloseSession         = %p\n", (void*)pCloseSession);
    printf("    Hub_GetLastErrorCode     = %p\n", (void*)pGetLastErr);

    if (!pGetState) {
        printf("[!] No se encontro Hub_GetActiveLicenseState\n");
        FreeLibrary(h);
        return 1;
    }

    /* Probamos llamar directo con argumentos nulos/cero, sin sesion valida,
       para observar el codigo de retorno (HRESULT) y el estado de licencia
       que escribe en el ultimo parametro (arg_14h en el desensamblado). */
    int state = 0xDEADBEEF;
    void* fakeArg = NULL;

    printf("\n[*] Llamando Hub_GetActiveLicenseState(NULL, NULL, NULL, &state) ...\n");
    int hr = pGetState(fakeArg, fakeArg, fakeArg, &state);
    printf("    HRESULT devuelto = 0x%08X\n", (unsigned)hr);
    printf("    *state (ActiveLicenseState) = 0x%08X (%d)\n", (unsigned)state, state);

    if (pGetLastErr) {
        int err = pGetLastErr(fakeArg);
        printf("    Hub_GetLastErrorCode = 0x%08X\n", (unsigned)err);
    }

    FreeLibrary(h);
    printf("\n[*] Fin del test.\n");
    return 0;
}
