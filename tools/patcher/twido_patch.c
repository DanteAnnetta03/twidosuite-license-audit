/*
 * twido_patch.c  -  PoC de auditoria de seguridad autorizada. NO distribuir.
 *
 * Aplica el "patch universal" sobre BrickLicenceManager.dll (TwidoSuite 2.3):
 * el producto entra REGISTRADO tanto en instalacion nueva como con el periodo
 * de prueba VENCIDO. Dos cambios, localizados DINAMICAMENTE (sin offset fijo),
 * con verificacion del patron esperado antes de escribir:
 *
 *   U1) pp_expired (export) -> stub "XOR EAX,EAX; RET 4" (31 C0 C2 04 00).
 *       pp_expired es el unico primitivo de expiracion: forzarlo a 0 = nunca expira.
 *   U2) codigo de estado de licencia (patron unico de 14 bytes):
 *       8B 55 08 C7 02 0B 00 00 00 E9 27 01 00 00  ->  el 0x0B pasa a 0x0F
 *       (estado 0x0B "LS_DEMO/no registrado" -> 0x0F "permanente/registrado").
 *
 * Ubicacion esperada del .exe: la carpeta principal de TwidoSuite. La DLL se
 * busca en  .\Registration\BrickLicenceManager.dll  (relativa al .exe). Tambien
 * se puede pasar una ruta explicita como argumento.
 *
 * Backup automatico una sola vez en <dll>.orig_backup. Idempotente.
 * Para revertir usar twido_restore.exe.
 *
 * Build:  i686-w64-mingw32-gcc -O2 -o twido_patch.exe twido_patch.c -lgdi32
 *         (ver Makefile / README para Windows nativo)
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUTHOR       "Dante Annetta"
#define APP_TITLE    "TwidoSuite Patch"
#define DLL_RELPATH  "Registration\\BrickLicenceManager.dll"

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

static char g_err[1024];                 /* mensaje de error exacto (para el box) */
static void set_err(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap); va_end(ap);
}

static u8* read_file(const char* path, long* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    u8* buf = (u8*)malloc(n > 0 ? n : 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f); *out_len = n; return buf;
}
static int write_file(const char* path, const u8* buf, long len) {
    FILE* f = fopen(path, "wb"); if (!f) return 0;
    int ok = (fwrite(buf, 1, len, f) == (size_t)len); fclose(f); return ok;
}
static int file_exists(const char* path) {
    FILE* f = fopen(path, "rb"); if (f) { fclose(f); return 1; } return 0;
}

static long rva_to_off(const u8* b, u32 rva) {
    u32 e_lfanew = *(u32*)(b + 0x3C);
    const u8* fh = b + e_lfanew + 4;
    u16 nsec = *(u16*)(fh + 2);
    u16 opt_sz = *(u16*)(fh + 16);
    const u8* sec = fh + 20 + opt_sz;
    for (int i = 0; i < nsec; i++) {
        const u8* s = sec + i*40;
        u32 vaddr = *(u32*)(s + 12), vsize = *(u32*)(s + 8), praw = *(u32*)(s + 20);
        if (rva >= vaddr && rva < vaddr + vsize) return (long)(praw + (rva - vaddr));
    }
    return -1;
}
static u32 find_export_rva(const u8* b, const char* name) {
    u32 e_lfanew = *(u32*)(b + 0x3C);
    const u8* opt = b + e_lfanew + 24;
    u32 exp_rva = *(u32*)(opt + 96);
    if (!exp_rva) return 0;
    long exp_off = rva_to_off(b, exp_rva); if (exp_off < 0) return 0;
    const u8* ed = b + exp_off;
    u32 nNames = *(u32*)(ed + 24), rvaFuncs = *(u32*)(ed + 28);
    u32 rvaNames = *(u32*)(ed + 32), rvaOrds = *(u32*)(ed + 36);
    long offFuncs = rva_to_off(b, rvaFuncs), offNames = rva_to_off(b, rvaNames), offOrds = rva_to_off(b, rvaOrds);
    if (offFuncs<0||offNames<0||offOrds<0) return 0;
    for (u32 i = 0; i < nNames; i++) {
        long nameOff = rva_to_off(b, *(u32*)(b + offNames + i*4));
        if (nameOff < 0) continue;
        if (strcmp((const char*)(b + nameOff), name) == 0) {
            u16 ord = *(u16*)(b + offOrds + i*2);
            return *(u32*)(b + offFuncs + ord*4);
        }
    }
    return 0;
}

/* Devuelve 1 OK, 0 error (set_err). *changed=1 si escribio algo. */
static int patch_pp_expired(u8* b, int* changed) {
    static const u8 stub[5] = {0x31,0xC0,0xC2,0x04,0x00};
    u32 rva = find_export_rva(b, "pp_expired");
    if (!rva) { set_err("No se encontro el export pp_expired. La DLL no parece ser la de TwidoSuite 2.3."); return 0; }
    long off = rva_to_off(b, rva);
    if (off < 0) { set_err("La RVA de pp_expired (0x%X) no mapea a un offset de archivo valido.", rva); return 0; }
    if (memcmp(b+off, stub, 5) == 0) return 1;                 /* ya aplicado */
    if (!(b[off]==0x55 && b[off+1]==0x8B && b[off+2]==0xEC)) {
        set_err("Prologo inesperado en pp_expired (%02X %02X %02X). Version de DLL no soportada.", b[off],b[off+1],b[off+2]);
        return 0;
    }
    memcpy(b+off, stub, 5); *changed = 1; return 1;
}
static int patch_state(u8* b, long len, int* changed) {
    static const u8 pat[14]     = {0x8B,0x55,0x08,0xC7,0x02,0x0B,0x00,0x00,0x00,0xE9,0x27,0x01,0x00,0x00};
    static const u8 patched[14] = {0x8B,0x55,0x08,0xC7,0x02,0x0F,0x00,0x00,0x00,0xE9,0x27,0x01,0x00,0x00};
    long hit = -1; int count = 0, already = 0;
    for (long i = 0; i + 14 <= len; i++) {
        if (memcmp(b+i, pat, 14) == 0) { hit = i; count++; }
        else if (memcmp(b+i, patched, 14) == 0) already++;
    }
    if (already > 0 && count == 0) return 1;                   /* ya aplicado */
    if (count == 0) { set_err("No se encontro el patron del codigo de estado de licencia. Version de DLL no soportada."); return 0; }
    if (count > 1)  { set_err("El patron del codigo de estado es ambiguo (%d coincidencias). Abortado por seguridad.", count); return 0; }
    b[hit+5] = 0x0F; *changed = 1; return 1;
}

/* Ruta por defecto:  <carpeta del .exe>\Registration\BrickLicenceManager.dll */
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

    if (!file_exists(dll)) {
        set_err("No se encontro la DLL:\n%s\n\nColoca este ejecutable en la carpeta principal de TwidoSuite\n(donde esta la subcarpeta Registration), o pasa la ruta como argumento.", dll);
        box_err(); return 1;
    }

    long len; u8* b = read_file(dll, &len);
    if (!b) { set_err("No se pudo leer la DLL:\n%s", dll); box_err(); return 1; }

    char backup[MAX_PATH]; snprintf(backup, sizeof backup, "%s.orig_backup", dll);
    if (!file_exists(backup)) {
        if (!write_file(backup, b, len)) {
            set_err("No se pudo crear el backup:\n%s\n\nVerifica permisos de escritura (ejecuta como Administrador).", backup);
            free(b); box_err(); return 1;
        }
    }

    int ch1 = 0, ch2 = 0;
    if (!patch_pp_expired(b, &ch1)) { free(b); box_err(); return 1; }
    if (!patch_state(b, len, &ch2)) { free(b); box_err(); return 1; }

    if (ch1 || ch2) {
        if (!write_file(dll, b, len)) {
            set_err("No se pudo escribir la DLL parcheada:\n%s\n\nVerifica permisos (ejecuta como Administrador) y que TwidoSuite este cerrado.", dll);
            free(b); box_err(); return 1;
        }
    }
    free(b);
    box_ok();
    return 0;
}
