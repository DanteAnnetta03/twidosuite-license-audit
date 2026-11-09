/*
 * twido_restore.c  -  PoC de auditoria de seguridad autorizada. NO distribuir.
 *
 * Restaura BrickLicenceManager.dll a su estado ORIGINAL desde el backup que crea
 * twido_patch.exe (<dll>.orig_backup). Repara la instalacion si algo salio mal.
 *
 * Ubicacion esperada del .exe: la carpeta principal de TwidoSuite. La DLL (y su
 * backup) se buscan en  .\Registration\  (relativo al .exe). Tambien acepta una
 * ruta explicita de la DLL como argumento.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -o twido_restore.exe twido_restore.c -lgdi32
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUTHOR       "Dante Annetta"
#define APP_TITLE    "TwidoSuite Restore"
#define DLL_RELPATH  "Registration\\BrickLicenceManager.dll"

static char g_err[1024];
static void set_err(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap); va_end(ap);
}
static int file_exists(const char* p) { FILE* f = fopen(p,"rb"); if (f){fclose(f);return 1;} return 0; }

static int copy_over(const char* src, const char* dst) {
    FILE* fi = fopen(src, "rb"); if (!fi) return 0;
    fseek(fi, 0, SEEK_END); long n = ftell(fi); fseek(fi, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(n > 0 ? n : 1);
    if (!buf) { fclose(fi); return 0; }
    int ok = (fread(buf,1,n,fi) == (size_t)n); fclose(fi);
    if (ok) { FILE* fo = fopen(dst,"wb"); if (!fo){free(buf);return 0;} ok = (fwrite(buf,1,n,fo)==(size_t)n); fclose(fo); }
    free(buf); return ok;
}

static void default_dll_path(char* out, size_t n) {
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    char* slash = strrchr(exe, '\\'); if (slash) *(slash+1) = 0;
    snprintf(out, n, "%s%s", exe, DLL_RELPATH);
}

static void box_ok(void)  { MessageBoxA(NULL, "Done.\n\n- " AUTHOR, APP_TITLE, MB_OK | MB_ICONINFORMATION); }
static void box_err(void) { MessageBoxA(NULL, g_err[0]?g_err:"Error desconocido.", APP_TITLE " - Error", MB_OK | MB_ICONERROR); }

int main(int argc, char** argv) {
    char dll[MAX_PATH]; dll[0] = 0;
    for (int i = 1; i < argc; i++) if (argv[i][0] != '-') { strncpy(dll, argv[i], MAX_PATH-1); dll[MAX_PATH-1]=0; }
    if (!dll[0]) default_dll_path(dll, sizeof dll);

    char backup[MAX_PATH]; snprintf(backup, sizeof backup, "%s.orig_backup", dll);

    if (!file_exists(backup)) {
        set_err("No se encontro el backup original:\n%s\n\nNo hay nada que restaurar (quiza nunca se aplico el patch, o el backup fue movido).", backup);
        box_err(); return 1;
    }
    if (!copy_over(backup, dll)) {
        set_err("No se pudo restaurar la DLL desde el backup.\n\nVerifica permisos (ejecuta como Administrador) y que TwidoSuite este cerrado.\n\nDestino: %s", dll);
        box_err(); return 1;
    }
    box_ok();
    return 0;
}
