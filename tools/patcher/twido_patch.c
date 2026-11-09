/*
 * twido_patch.c  -  PoC de auditoria de seguridad autorizada. NO distribuir.
 *
 * Aplica el "patch universal" sobre BrickLicenceManager.dll (TwidoSuite 2.3),
 * que hace que el producto entre REGISTRADO tanto en fresh install como con el
 * periodo de prueba VENCIDO. Dos cambios, localizados DINAMICAMENTE (no por
 * offset fijo), con verificacion del patron esperado antes de escribir:
 *
 *   U1) pp_expired  (export de la DLL) -> stub "XOR EAX,EAX; RET 4"
 *       (31 C0 C2 04 00). pp_expired es el unico primitivo por el que pasan
 *       TODAS las decisiones de expiracion (confirmado empiricamente: forzarlo
 *       a 1 -> "License is expired"; a 0 -> nunca expira). __stdcall, 1 arg.
 *
 *   U2) codigo de estado de licencia en la rutina interna que alimenta a
 *       Hub_GetActiveLicenseState: la instruccion
 *         MOV EDX,[EBP+8] ; MOV dword ptr [EDX], 0x0B
 *         (bytes  8B 55 08 C7 02 0B 00 00 00)
 *       escribe el estado 0x0B (LS_DEMO activo / "no registrado"). Se cambia el
 *       inmediato 0x0B -> 0x0F (permanente / registrado). La GUI lee ese estado.
 *
 * Backup automatico UNA vez en <dll>.orig_backup. Idempotente. --restore revierte.
 *
 * Uso:
 *   twido_patch.exe                       (autodetecta la DLL junto al .exe)
 *   twido_patch.exe "C:\ruta\BrickLicenceManager.dll"
 *   twido_patch.exe --restore             (restaura desde el backup)
 *
 * Build: i686-w64-mingw32-gcc -O2 -o twido_patch.exe twido_patch.c -lgdi32
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

static char g_report[4096];
static void report(const char* fmt, ...) {
    char line[1024]; va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap); va_end(ap);
    printf("%s\n", line);
    strncat(g_report, line, sizeof(g_report)-strlen(g_report)-2);
    strncat(g_report, "\n", sizeof(g_report)-strlen(g_report)-2);
}

/* Lee todo el archivo a memoria. */
static u8* read_file(const char* path, long* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    u8* buf = (u8*)malloc(n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f); *out_len = n; return buf;
}
static int write_file(const char* path, const u8* buf, long len) {
    FILE* f = fopen(path, "wb");
    if (!f) return 0;
    int ok = (fwrite(buf, 1, len, f) == (size_t)len);
    fclose(f); return ok;
}
static int file_exists(const char* path) {
    FILE* f = fopen(path, "rb"); if (f) { fclose(f); return 1; } return 0;
}

/* Mapea una RVA a offset de archivo usando los section headers. */
static long rva_to_off(const u8* b, long len, u32 rva) {
    u32 e_lfanew = *(u32*)(b + 0x3C);
    const u8* nt = b + e_lfanew;                 /* PE signature */
    const u8* fh = nt + 4;                        /* IMAGE_FILE_HEADER */
    u16 nsec = *(u16*)(fh + 2);
    u16 opt_sz = *(u16*)(fh + 16);
    const u8* sec = fh + 20 + opt_sz;             /* section table */
    for (int i = 0; i < nsec; i++) {
        const u8* s = sec + i*40;
        u32 vaddr = *(u32*)(s + 12);
        u32 vsize = *(u32*)(s + 8);
        u32 praw  = *(u32*)(s + 20);
        if (rva >= vaddr && rva < vaddr + vsize)
            return (long)(praw + (rva - vaddr));
    }
    return -1;
}

/* Encuentra la RVA de un export por nombre. */
static u32 find_export_rva(const u8* b, long len, const char* name) {
    u32 e_lfanew = *(u32*)(b + 0x3C);
    const u8* nt = b + e_lfanew;
    const u8* opt = nt + 24;                       /* IMAGE_OPTIONAL_HEADER32 */
    u32 exp_rva = *(u32*)(opt + 96);               /* DataDirectory[0].VirtualAddress */
    if (!exp_rva) return 0;
    long exp_off = rva_to_off(b, len, exp_rva);
    if (exp_off < 0) return 0;
    const u8* ed = b + exp_off;
    u32 nNames   = *(u32*)(ed + 24);
    u32 rvaFuncs = *(u32*)(ed + 28);
    u32 rvaNames = *(u32*)(ed + 32);
    u32 rvaOrds  = *(u32*)(ed + 36);
    long offFuncs = rva_to_off(b, len, rvaFuncs);
    long offNames = rva_to_off(b, len, rvaNames);
    long offOrds  = rva_to_off(b, len, rvaOrds);
    if (offFuncs<0||offNames<0||offOrds<0) return 0;
    for (u32 i = 0; i < nNames; i++) {
        u32 nameRva = *(u32*)(b + offNames + i*4);
        long nameOff = rva_to_off(b, len, nameRva);
        if (nameOff < 0) continue;
        if (strcmp((const char*)(b + nameOff), name) == 0) {
            u16 ord = *(u16*)(b + offOrds + i*2);
            return *(u32*)(b + offFuncs + ord*4);
        }
    }
    return 0;
}

/* --------- patches ---------- */

/* U1: pp_expired -> XOR EAX,EAX; RET 4 */
static int patch_pp_expired(u8* b, long len) {
    u32 rva = find_export_rva(b, len, "pp_expired");
    if (!rva) { report("[U1] ERROR: export pp_expired no encontrado"); return 0; }
    long off = rva_to_off(b, len, rva);
    if (off < 0) { report("[U1] ERROR: RVA de pp_expired no mapea a offset"); return 0; }
    static const u8 stub[5] = {0x31,0xC0,0xC2,0x04,0x00};  /* xor eax,eax; ret 4 */
    if (memcmp(b+off, stub, 5) == 0) { report("[U1] ya aplicado (pp_expired stub)"); return 1; }
    /* prologo tipico esperado: 55 8B EC (push ebp; mov ebp,esp) */
    if (!(b[off]==0x55 && b[off+1]==0x8B && b[off+2]==0xEC)) {
        report("[U1] ERROR: prologo inesperado en pp_expired (%02x %02x %02x)", b[off],b[off+1],b[off+2]);
        return 0;
    }
    memcpy(b+off, stub, 5);
    report("[U1] pp_expired @ RVA 0x%X (off 0x%lX) -> stub xor eax,eax; ret 4", rva, off);
    return 1;
}

/* U2: patron de 14 bytes UNICO del caso LS_DEMO (la escritura de estado 0x0B
 *     seguida del JMP que lo distingue del caso LS_PERIODIC):
 *       8B 55 08 C7 02 0B 00 00 00 E9 27 01 00 00
 *     Cambia el inmediato 0x0B (pos +5) -> 0x0F. */
static int patch_state(u8* b, long len) {
    static const u8 pat[14]     = {0x8B,0x55,0x08,0xC7,0x02,0x0B,0x00,0x00,0x00,0xE9,0x27,0x01,0x00,0x00};
    static const u8 patched[14] = {0x8B,0x55,0x08,0xC7,0x02,0x0F,0x00,0x00,0x00,0xE9,0x27,0x01,0x00,0x00};
    long hit = -1; int count = 0, already = 0;
    for (long i = 0; i + 14 <= len; i++) {
        if (memcmp(b+i, pat, 14) == 0) { hit = i; count++; }
        else if (memcmp(b+i, patched, 14) == 0) { already++; }
    }
    if (already > 0 && count == 0) { report("[U2] ya aplicado (estado 0x0F)"); return 1; }
    if (count == 0) { report("[U2] ERROR: patron de estado no encontrado"); return 0; }
    if (count > 1)  { report("[U2] ERROR: patron ambiguo (%d coincidencias), abortando", count); return 0; }
    b[hit+5] = 0x0F;   /* 0x0B -> 0x0F */
    report("[U2] estado @ off 0x%lX : 0x0B -> 0x0F (registrado)", hit+5);
    return 1;
}

static void show_box(const char* title) {
    MessageBoxA(NULL, g_report, title, MB_OK | MB_ICONINFORMATION);
}

/* localiza la DLL junto al .exe si no se paso ruta */
static void default_dll_path(char* out, size_t n) {
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    char* slash = strrchr(exe, '\\');
    if (slash) *(slash+1) = 0;
    snprintf(out, n, "%sBrickLicenceManager.dll", exe);
}

int main(int argc, char** argv) {
    g_report[0] = 0;
    report("=== twido_patch (PoC auditoria) : patch UNIVERSAL ===");

    int restore = 0;
    char dll[MAX_PATH]; dll[0] = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--restore") == 0) restore = 1;
        else if (argv[i][0] != '-') { strncpy(dll, argv[i], MAX_PATH-1); dll[MAX_PATH-1]=0; }
    }
    if (!dll[0]) default_dll_path(dll, sizeof dll);
    report("[*] DLL: %s", dll);

    char backup[MAX_PATH]; snprintf(backup, sizeof backup, "%s.orig_backup", dll);

    if (restore) {
        if (!file_exists(backup)) { report("[!] No hay backup que restaurar."); show_box("twido_patch"); return 1; }
        long n; u8* b = read_file(backup, &n);
        if (!b || !write_file(dll, b, n)) { report("[!] Fallo al restaurar."); show_box("twido_patch"); return 1; }
        free(b); report("[+] Restaurado desde el backup original."); show_box("twido_patch"); return 0;
    }

    long len; u8* b = read_file(dll, &len);
    if (!b) { report("[!] No se pudo abrir la DLL."); show_box("twido_patch"); return 1; }
    report("[*] %ld bytes leidos", len);

    /* backup una sola vez */
    if (!file_exists(backup)) {
        if (write_file(backup, b, len)) report("[+] Backup -> %s", backup);
        else report("[!] No se pudo crear backup (continuo igual)");
    } else {
        report("[*] Backup ya existia (no se sobreescribe)");
    }

    int ok1 = patch_pp_expired(b, len);
    int ok2 = patch_state(b, len);

    if (ok1 && ok2) {
        if (write_file(dll, b, len)) report("[+] OK: patch universal escrito. TwidoSuite entrara REGISTRADO (fresh y vencido).");
        else report("[!] ERROR al escribir la DLL.");
    } else {
        report("[!] Algun patch fallo; NO se escribio nada. (Revisar version de la DLL.)");
    }
    free(b);
    show_box("twido_patch");
    return (ok1 && ok2) ? 0 : 1;
}
