#include <windows.h>
#include <stdio.h>

typedef int (__stdcall *Hub_OpenSession_t)(const char* a1, const char* a2, int a3, const char* a4, void* outHandle);
typedef int (__stdcall *Hub_GetActiveLicenseState_t)(void* session, void* a2, void* a3, int* outState);
typedef int (__stdcall *Hub_GetActiveTrialInfo_t)(void* session, void* a2, void* a3, void* outInfo);
typedef int (__stdcall *Hub_GetLastErrorString_t)(void* session, char* buf, int* len);

int main(int argc, char** argv) {
    const char* p1 = (argc>1)? argv[1] : "TWDBTFU10ES";
    const char* p2 = (argc>2)? argv[2] : "";
    int         p3 = (argc>3)? atoi(argv[3]) : 0;
    const char* p4 = (argc>4)? argv[4] : "";

    HMODULE h = LoadLibraryA("BrickLicenceManager.dll");
    if(!h){ printf("LoadLibrary fail %lu\n", GetLastError()); return 1; }
    Hub_OpenSession_t OpenSession = (Hub_OpenSession_t)GetProcAddress(h,"Hub_OpenSession");
    Hub_GetActiveLicenseState_t GetState = (Hub_GetActiveLicenseState_t)GetProcAddress(h,"Hub_GetActiveLicenseState");
    Hub_GetActiveTrialInfo_t GetTrial = (Hub_GetActiveTrialInfo_t)GetProcAddress(h,"Hub_GetActiveTrialInfo");

    printf("OpenSession=%p GetState=%p GetTrial=%p\n",(void*)OpenSession,(void*)GetState,(void*)GetTrial);

    unsigned char handle[64]; memset(handle,0,sizeof(handle));
    printf("[*] Hub_OpenSession(\"%s\",\"%s\",%d,\"%s\",&handle)\n", p1,p2,p3,p4);
    int hr = OpenSession(p1,p2,p3,p4,handle);
    printf("    HRESULT=0x%08X\n",(unsigned)hr);
    printf("    handle[0..15]: ");
    for(int i=0;i<16;i++) printf("%02x ",handle[i]);
    printf("\n");

    /* El handle devuelto: primer dword suele ser el puntero a la sesion */
    void* session = *(void**)handle;
    printf("    session ptr = %p\n", session);

    if(hr>=0 && session){
        int state=0xDEADBEEF;
        int hr2 = GetState(session,NULL,NULL,&state);
        printf("[*] Hub_GetActiveLicenseState -> hr=0x%08X state=0x%08X (%d)\n",(unsigned)hr2,(unsigned)state,state);
    }
    return 0;
}
