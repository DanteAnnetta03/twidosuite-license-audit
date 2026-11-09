/*
 * PoC de auditoria de seguridad - uso autorizado unicamente, NO distribuir.
 *
 * Demostracion GET -> SET -> GET 100% programatica sobre BrickLicenceManager.dll:
 *   1. Hub_OpenSession("TwidoSuite","02.50",...)  -> handle de sesion valido
 *      (requiere la DLL doble-parcheada: gate 0x11809 JZ->JMP + opensession 0x118D8)
 *   2. Hub_GetLicenseFileFlag(handle, idx, &valor)   -> lee estado actual
 *   3. Hub_SetLicenseFileFlag(handle, idx, nuevo)    -> escribe estado
 *   4. Hub_GetLicenseFileFlag(handle, idx, &valor2)  -> relee para confirmar
 *
 * Firmas confirmadas por decompilacion Ghidra:
 *   int __stdcall Hub_OpenSession(const char* product, const char* version,
 *                                 int p3, const char* challenge, unsigned* outHandle)
 *   int __stdcall Hub_GetLicenseFileFlag(unsigned handle, int idx, int* outVal)
 *   int __stdcall Hub_SetLicenseFileFlag(unsigned handle, int idx, int val)
 * El selector de flag interno actua solo con idx==1 (FUN_1002860e/FUN_10028650).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (__stdcall *OpenSession_t)(const char*, const char*, int, const char*, unsigned*);
typedef int (__stdcall *GetFlag_t)(unsigned, int, int*);
typedef int (__stdcall *SetFlag_t)(unsigned, int, int);

int main(int argc, char** argv) {
    const char* product = (argc>1)? argv[1] : "TwidoSuite";
    const char* version = (argc>2)? argv[2] : "02.50";
    int idx    = (argc>3)? atoi(argv[3]) : 1;
    int newval = (argc>4)? atoi(argv[4]) : 1;

    HMODULE h = LoadLibraryA("BrickLicenceManager.dll");
    if(!h){ printf("LoadLibrary fail %lu\n", GetLastError()); return 1; }

    OpenSession_t OpenSession = (OpenSession_t)GetProcAddress(h,"Hub_OpenSession");
    GetFlag_t     GetFlag     = (GetFlag_t)GetProcAddress(h,"Hub_GetLicenseFileFlag");
    SetFlag_t     SetFlag     = (SetFlag_t)GetProcAddress(h,"Hub_SetLicenseFileFlag");
    printf("OpenSession=%p GetFlag=%p SetFlag=%p\n",(void*)OpenSession,(void*)GetFlag,(void*)SetFlag);

    unsigned handle = 0xFFFFFFFF;
    /* param_4 es in/out: OpenSession ESCRIBE un resultado ahi al exito
       (FUN_10054f80 @ 0x10054f80). Debe ser un buffer escribible y amplio. */
    char challenge[512]; memset(challenge, 0, sizeof(challenge));
    int hr = OpenSession(product, version, 0, challenge, &handle);
    printf("[OpenSession] product=\"%s\" version=\"%s\"  hr=0x%08X  handle=0x%08X\n",
           product, version, (unsigned)hr, handle);
    if(hr < 0 || handle == 0xFFFFFFFF){ printf("  -> sesion NO abierta, aborto\n"); return 2; }

    int before = 0xDEAD;
    int g1 = GetFlag(handle, idx, &before);
    printf("[GET #1]  idx=%d  hr=0x%08X  value=%d (0x%08X)\n", idx,(unsigned)g1,before,(unsigned)before);

    int s = SetFlag(handle, idx, newval);
    printf("[SET]     idx=%d  val=%d  hr=0x%08X\n", idx, newval,(unsigned)s);

    int after = 0xDEAD;
    int g2 = GetFlag(handle, idx, &after);
    printf("[GET #2]  idx=%d  hr=0x%08X  value=%d (0x%08X)\n", idx,(unsigned)g2,after,(unsigned)after);

    printf("\n== RESUMEN ==  before=%d  after=%d  -> %s\n",
           before, after, (before!=after)? "[CAMBIO DE ESTADO OBSERVADO]" : "[sin cambio]");
    return 0;
}
