/*
 * PoC de auditoria de seguridad - uso autorizado unicamente, NO distribuir.
 *
 * Tres mecanismos de parche sobre BrickLicenceManager.dll, segun el target:
 *
 * (A) Reemplazo de funcion completa (target "expiration"):
 *     reemplaza la funcion desde su primer byte por un stub de 15 bytes que
 *     siempre devuelve S_OK con un valor de salida elegido por --value.
 *     ADVERTENCIA (confirmado empiricamente): este mecanismo rompe el calculo
 *     interno real de dias/fechas en "license" y "trial" (saltea efectos
 *     secundarios necesarios) - por eso esas dos NO usan mas este mecanismo.
 *
 * (B) Forzar el veredicto de una validacion interna de 10KB, SIN saltearla
 *     (target "opensession"): dejar correr la llamada real (preserva sus
 *     efectos secundarios: pobla datos de sesion que Hub_LaunchRegistration
 *     necesita despues) y reemplazar el "cmp+jge" que evalua su resultado
 *     (offset +0x16f, 13 bytes) por un JMP incondicional al mismo destino
 *     de exito.
 *
 * (C) Mismo principio que (B) pero mas quirurgico (targets "license" y
 *     "trial"): ambas funciones son gemelas (mismo prologo/epilogo) y, en
 *     la rama "sin archivo de licencia" (caso trial), ambas tienen el MISMO
 *     patron en el MISMO offset relativo +0x208: "test eax,eax; jne <exito>"
 *     (2 bytes: 75 36) justo despues de llamar a la rutina real que computa
 *     el estado/dias. Se cambia el opcode jne (0x75) por jmp incondicional
 *     (0xEB), 1 solo byte, dejando correr la computacion real intacta:
 *       license -> Hub_GetActiveLicenseState (en su rama "sin licencia")
 *       trial   -> Hub_GetActiveTrialInfo    (en su rama "sin licencia")
 *     Validado en entorno de prueba limpio: no rompe nada (mismo resultado
 *     que sin parchear cuando el trial esta genuinamente vigente). Pendiente
 *     de confirmar el efecto en un entorno con trial expirado.
 *
 * Localiza las funciones DINAMICAMENTE via la tabla de exports del PE (no
 * usa un offset fijo para encontrarlas), y verifica el patron de bytes
 * esperado antes de escribir nada. Hace backup automatico UNA sola vez
 * (.orig_backup), de forma que correr esta herramienta varias veces con
 * distintos --target no pisa el backup del original sin parchear. Muestra
 * un dialogo (MessageBox) con el resultado final ademas de la consola.
 *
 * Uso:
 *   patch_brick.exe                                   (target=license, autodetecta la carpeta)
 *   patch_brick.exe --target trial
 *   patch_brick.exe --target opensession
 *   patch_brick.exe --target expiration --value 0     (mecanismo A, el unico que usa --value)
 *   patch_brick.exe --restore                         (restaura TODO al original desde el backup)
 *   patch_brick.exe "C:\ruta\a\BrickLicenceManager.dll" --target license
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

/* variant 0 (A) -> reemplazo de funcion completa con STUB + --value, en offset 0
 * variant 1 (B) -> bypass de 13 bytes (cmp+jge -> jmp+nops) en body_offset
 * variant 2 (C) -> 1 byte jne->jmp en body_offset
 *   body_prologue/_len -> prologo esperado de la funcion completa (chequeo extra en B/C)
 */
typedef struct {
    const char *key;
    const char *export_name;
    int variant;
    u32 body_offset;
    const u8 *body_prologue;
    int body_prologue_len;
} TargetDef;

static const u8 OPENSESSION_PROLOGUE[9] = {0x55,0x8B,0xEC,0x81,0xEC,0xE0,0x00,0x00,0x00};
static const u8 TWIN_PROLOGUE[9]        = {0x55,0x8B,0xEC,0x81,0xEC,0xCC,0x00,0x00,0x00};

static const TargetDef TARGETS[] = {
    { "license",     "Hub_GetActiveLicenseState",     2, 0x208, TWIN_PROLOGUE,        9 },
    { "trial",       "Hub_GetActiveTrialInfo",         2, 0x208, TWIN_PROLOGUE,        9 },
    { "expiration",  "Hub_GetActiveExpirationPolicy",  0, 0,     NULL,                 0 },
    { "opensession", "Hub_OpenSession",                1, 0x16f, OPENSESSION_PROLOGUE, 9 },
};
#define NUM_TARGETS (sizeof(TARGETS)/sizeof(TARGETS[0]))

/* Stub generico de 15 bytes para el mecanismo (A). El inmediato de
 * "mov dword [eax], VALOR" se sobreescribe en runtime segun --value:
 *   mov eax, [esp+0x10]        8B 44 24 10
 *   mov dword [eax], VALOR     C7 00 <imm32 LE>
 *   xor eax, eax               33 C0
 *   ret 0x10                   C2 10 00
 */
static u8 STUB[] = {
    0x8B,0x44,0x24,0x10,
    0xC7,0x00,0x00,0x00,0x00,0x00,   /* bytes 6..9 = imm32 del valor */
    0x33,0xC0,
    0xC2,0x10,0x00
};
#define STUB_LEN (sizeof(STUB))
#define STUB_IMM_OFFSET 6

/* Patch de 13 bytes para el mecanismo (B): reemplaza "cmp dword[var],0"
 * (7 bytes) + "jge <exito>" (6 bytes) por "jmp <exito>" (5 bytes) + 8 NOPs,
 * mismo tamaño exacto (13 bytes). El CALL anterior a esto NO se toca. */
#define CALL_BYPASS_LEN 13
static const u8 CALL_BYPASS_EXPECTED[CALL_BYPASS_LEN] = {
    0x83,0xBD,0x58,0xFF,0xFF,0xFF,0x00,   /* cmp dword [ebp-0xa8], 0 */
    0x0F,0x8D,0xA4,0x00,0x00,0x00         /* jge 0x10011989 */
};
static const u8 CALL_BYPASS_PATCH[CALL_BYPASS_LEN] = {
    0xE9,0xAC,0x00,0x00,0x00,             /* jmp 0x10011989 (mismo destino) */
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 /* padding */
};

/* Patch de 1 byte para el mecanismo (C): "jne <exito>" (75 36) -> "jmp <exito>"
 * (EB 36), mismo destino, mismo tamaño (2 bytes, solo el opcode cambia). */
#define JNE_JMP_LEN 2
static const u8 JNE_JMP_EXPECTED[JNE_JMP_LEN] = {0x75,0x36};
static const u8 JNE_JMP_PATCH[JNE_JMP_LEN]    = {0xEB,0x36};

static const u8 EXPECTED_PROLOGUE[3] = {0x55,0x8B,0xEC};

static char g_result[2048] = "";
static int  g_is_error = 0;

static void set_result(int is_error, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_result, sizeof(g_result), fmt, ap);
    va_end(ap);
    g_is_error = is_error;
}

static u8 *read_file(const char *path, long *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[!] No se pudo abrir %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *buf = (u8*)malloc(sz);
    if (!buf) { fclose(f); fprintf(stderr, "[!] Sin memoria\n"); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        fclose(f); free(buf); fprintf(stderr, "[!] Error leyendo archivo\n"); return NULL;
    }
    fclose(f);
    *out_size = sz;
    return buf;
}

static int write_file(const char *path, const u8 *buf, long sz) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "[!] No se pudo escribir %s\n", path); return 0; }
    size_t w = fwrite(buf, 1, sz, f);
    fclose(f);
    return w == (size_t)sz;
}

static int copy_file(const char *src, const char *dst) {
    long sz;
    u8 *buf = read_file(src, &sz);
    if (!buf) return 0;
    int ok = write_file(dst, buf, sz);
    free(buf);
    return ok;
}

typedef struct { char name[9]; u32 vaddr, vsize, rawptr, rawsize; } Section;

static int check_full_prologue(const u8 *data, long file_off, const TargetDef *t) {
    if (!t->body_prologue || t->body_prologue_len <= 0) return 1;
    return memcmp(data + file_off, t->body_prologue, t->body_prologue_len) == 0;
}

static long rva_to_file_offset(Section *secs, int nsec, u32 rva, int *found) {
    for (int i = 0; i < nsec; i++) {
        if (rva >= secs[i].vaddr && rva < secs[i].vaddr + secs[i].vsize) {
            *found = 1;
            return secs[i].rawptr + (rva - secs[i].vaddr);
        }
    }
    *found = 0;
    return 0;
}

int main(int argc, char **argv) {
    char path[1024];
    int restore = 0;
    char *explicit_path = NULL;
    const char *target_key = "license";
    long value = 2;

    printf("=== patch_brick (PoC auditoria de seguridad) ===\n\n");

    /* Por defecto: asumimos que este .exe esta en la misma carpeta que
       BrickLicenceManager.dll (ej. la carpeta "Registration" de TwidoSuite),
       asi que no hace falta pasarle ningun path. Se puede sobreescribir
       pasando una ruta explicita como argumento si hiciera falta. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--restore") == 0) {
            restore = 1;
        } else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target_key = argv[++i];
        } else if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            value = strtol(argv[++i], NULL, 0); /* acepta decimal o 0x... */
        } else if (argv[i][0] != '-') {
            explicit_path = argv[i];
        }
    }

    const TargetDef *target = NULL;
    for (size_t i = 0; i < NUM_TARGETS; i++) {
        if (strcmp(TARGETS[i].key, target_key) == 0) { target = &TARGETS[i]; break; }
    }
    if (!target) {
        set_result(1, "Target desconocido: '%s'.\nValidos: license, trial, opensession, expiration.", target_key);
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }
    const char *TARGET_EXPORT = target->export_name;
    if (target->variant == 0) {
        STUB[STUB_IMM_OFFSET]   = (u8)(value & 0xFF);
        STUB[STUB_IMM_OFFSET+1] = (u8)((value >> 8) & 0xFF);
        STUB[STUB_IMM_OFFSET+2] = (u8)((value >> 16) & 0xFF);
        STUB[STUB_IMM_OFFSET+3] = (u8)((value >> 24) & 0xFF);
        printf("[*] Target: %s (%s)   Valor a forzar: %ld (0x%lx)\n", target_key, TARGET_EXPORT, value, value);
    } else {
        printf("[*] Target: %s (%s)   Mecanismo: forzar veredicto en +0x%x (--value no aplica)\n",
               target_key, TARGET_EXPORT, target->body_offset);
    }

    if (explicit_path) {
        strncpy(path, explicit_path, sizeof(path)-1);
        path[sizeof(path)-1] = 0;
    } else {
        char exe_path[1024];
        DWORD n = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
        if (n == 0 || n >= sizeof(exe_path)) {
            set_result(1, "No se pudo determinar la carpeta del ejecutable.");
            fprintf(stderr, "[!] %s\n", g_result);
            goto show_and_exit;
        }
        char *slash = strrchr(exe_path, '\\');
        if (slash) *slash = 0; else exe_path[0] = 0;
        snprintf(path, sizeof(path), "%s\\BrickLicenceManager.dll", exe_path);
        printf("[*] Sin ruta explicita: usando la carpeta del .exe:\n    %s\n", path);
    }

    /* Verificamos que el archivo exista antes de seguir, para dar un
       mensaje claro si el .exe no esta en la carpeta correcta. */
    FILE *exist_test = fopen(path, "rb");
    if (!exist_test) {
        set_result(1,
            "No se encontro BrickLicenceManager.dll en:\n%s\n\n"
            "Este .exe debe copiarse dentro de la carpeta \"Registration\"\n"
            "de la instalacion de TwidoSuite (junto a BrickLicenceManager.dll),\n"
            "o se le puede pasar la ruta completa como argumento:\n"
            "  patch_brick.exe \"C:\\ruta\\BrickLicenceManager.dll\"",
            path);
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }
    fclose(exist_test);

    char backup_path[1040];
    snprintf(backup_path, sizeof(backup_path), "%s.orig_backup", path);

    if (restore) {
        FILE *test = fopen(backup_path, "rb");
        if (!test) {
            set_result(1, "No existe backup en:\n%s\n\nNo se puede restaurar.", backup_path);
            fprintf(stderr, "[!] %s\n", g_result);
            goto show_and_exit;
        }
        fclose(test);
        if (copy_file(backup_path, path)) {
            set_result(0, "Restaurado correctamente desde el backup:\n%s", path);
            printf("[+] %s\n", g_result);
        } else {
            set_result(1, "Fallo al restaurar el archivo original.");
            fprintf(stderr, "[!] %s\n", g_result);
        }
        goto show_and_exit;
    }

    long sz;
    u8 *data = read_file(path, &sz);
    if (!data) {
        set_result(1, "No se pudo abrir el archivo:\n%s", path);
        goto show_and_exit;
    }

    printf("[*] Analizando %s (%ld bytes)...\n", path, sz);

    if (sz < 0x400 || data[0] != 'M' || data[1] != 'Z') {
        set_result(1, "El archivo no es un PE valido (falta firma MZ):\n%s", path);
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }
    u32 e_lfanew = *(u32*)(data + 0x3C);
    if (e_lfanew + 24 >= (u32)sz || memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        set_result(1, "El archivo no es un PE valido (falta firma PE).");
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }

    u16 machine = *(u16*)(data + e_lfanew + 4);
    u16 nsec    = *(u16*)(data + e_lfanew + 6);
    if (machine != 0x14C) {
        set_result(1, "Se esperaba PE32 x86 (0x14c), se encontro 0x%x.\nAbortando.", machine);
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }
    u16 opt_hdr_size = *(u16*)(data + e_lfanew + 20);
    u32 opt_hdr_off  = e_lfanew + 24;
    u16 magic = *(u16*)(data + opt_hdr_off);
    if (magic != 0x10B) {
        set_result(1, "Optional header no es PE32. Abortando.");
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }
    u32 image_base      = *(u32*)(data + opt_hdr_off + 28);
    u32 export_dir_rva  = *(u32*)(data + opt_hdr_off + 96);

    printf("[*] ImageBase=0x%x, %d secciones\n", image_base, nsec);

    u32 sec_table = e_lfanew + 24 + opt_hdr_size;
    Section *secs = (Section*)malloc(sizeof(Section) * nsec);
    for (int i = 0; i < nsec; i++) {
        u32 off = sec_table + i * 40;
        memcpy(secs[i].name, data + off, 8);
        secs[i].name[8] = 0;
        secs[i].vsize   = *(u32*)(data + off + 8);
        secs[i].vaddr   = *(u32*)(data + off + 12);
        secs[i].rawsize = *(u32*)(data + off + 16);
        secs[i].rawptr  = *(u32*)(data + off + 20);
    }

    int found;
    long export_off = rva_to_file_offset(secs, nsec, export_dir_rva, &found);
    if (!found) {
        set_result(1, "No se pudo mapear el directorio de exports.\nEsta DLL no exporta funciones?");
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }

    u32 num_names    = *(u32*)(data + export_off + 24);
    u32 func_tbl_rva = *(u32*)(data + export_off + 28);
    u32 name_tbl_rva = *(u32*)(data + export_off + 32);
    u32 ord_tbl_rva  = *(u32*)(data + export_off + 36);

    long name_tbl_off = rva_to_file_offset(secs, nsec, name_tbl_rva, &found);
    if (!found) { set_result(1, "No se pudo mapear la tabla de nombres."); fprintf(stderr,"[!] %s\n",g_result); goto show_and_exit; }
    long ord_tbl_off = rva_to_file_offset(secs, nsec, ord_tbl_rva, &found);
    if (!found) { set_result(1, "No se pudo mapear la tabla de ordinales."); fprintf(stderr,"[!] %s\n",g_result); goto show_and_exit; }
    long func_tbl_off = rva_to_file_offset(secs, nsec, func_tbl_rva, &found);
    if (!found) { set_result(1, "No se pudo mapear la tabla de funciones."); fprintf(stderr,"[!] %s\n",g_result); goto show_and_exit; }

    u32 func_rva = 0;
    int match = 0;
    for (u32 i = 0; i < num_names; i++) {
        u32 name_rva = *(u32*)(data + name_tbl_off + i * 4);
        long name_off = rva_to_file_offset(secs, nsec, name_rva, &found);
        if (!found) continue;
        if (strcmp((const char*)(data + name_off), TARGET_EXPORT) == 0) {
            u16 ordinal = *(u16*)(data + ord_tbl_off + i * 2);
            func_rva = *(u32*)(data + func_tbl_off + ordinal * 4);
            match = 1;
            break;
        }
    }
    if (!match) {
        set_result(1, "No se encontro el export %s.\nEs esta la DLL correcta (BrickLicenceManager.dll)?", TARGET_EXPORT);
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }

    u32 func_va = image_base + func_rva;
    long file_off = rva_to_file_offset(secs, nsec, func_rva, &found);
    if (!found) {
        set_result(1, "No se pudo mapear la funcion a un offset de archivo.");
        fprintf(stderr, "[!] %s\n", g_result);
        goto show_and_exit;
    }

    printf("[+] %s encontrada:\n", TARGET_EXPORT);
    printf("    RVA=0x%x  VA=0x%x  FileOffset=0x%lx\n", func_rva, func_va, file_off);
    printf("[*] Bytes actuales en ese offset: ");
    for (int i = 0; i < 16; i++) printf("%02x", data[file_off+i]);
    printf("\n");

    int is_bypass = (target->variant != 0);
    long patch_off;
    const u8 *patch_bytes;
    size_t patch_len;
    const char *desc;

    if (target->variant == 1 || target->variant == 2) {
        /* Mecanismos (B)/(C): verificar el prologo completo de la funcion
           (mas estricto, porque no reemplazamos la funcion entera y
           necesitamos estar seguros de que el offset interno coincide). */
        if (!check_full_prologue(data, file_off, target)) {
            set_result(1,
                "ADVERTENCIA: el prologo de %s no coincide con el esperado.\n\n"
                "Esta build de la DLL puede diferir de la analizada en el laboratorio.\n"
                "No se escribio nada (abortado por seguridad).",
                TARGET_EXPORT);
            printf("[!] %s\n", g_result);
            free(data); free(secs);
            goto show_and_exit;
        }
        patch_off = file_off + target->body_offset;

        const u8 *expected = (target->variant == 1) ? CALL_BYPASS_EXPECTED : JNE_JMP_EXPECTED;
        const u8 *replacement = (target->variant == 1) ? CALL_BYPASS_PATCH : JNE_JMP_PATCH;
        size_t len = (target->variant == 1) ? CALL_BYPASS_LEN : JNE_JMP_LEN;

        if (memcmp(data + patch_off, expected, len) != 0) {
            char cur[CALL_BYPASS_LEN*2+1]; char exp[CALL_BYPASS_LEN*2+1];
            for (size_t i = 0; i < len; i++) {
                sprintf(cur+i*2, "%02x", data[patch_off+i]);
                sprintf(exp+i*2, "%02x", expected[i]);
            }
            set_result(1,
                "ADVERTENCIA: los bytes en el offset +0x%x de %s no coinciden\n"
                "con lo esperado (%s vs %s).\n\n"
                "Esta build de la DLL puede diferir de la analizada en el laboratorio.\n"
                "No se escribio nada (abortado por seguridad).",
                target->body_offset, TARGET_EXPORT, cur, exp);
            printf("[!] %s\n", g_result);
            free(data); free(secs);
            goto show_and_exit;
        }
        printf("[*] Offset de patch: +0x%x (VA=0x%lx)\n", target->body_offset, func_va + target->body_offset);
        printf("[*] Bytes actuales ahi: ");
        for (size_t i = 0; i < len; i++) printf("%02x", data[patch_off+i]);
        printf("\n");
        patch_bytes = replacement;
        patch_len = len;
        desc = (target->variant == 1)
            ? "forzar veredicto de exito (sin saltear la validacion real, 13 bytes)"
            : "forzar veredicto de exito (jne->jmp quirurgico, 1 byte)";
    } else {
        if (memcmp(data + file_off, EXPECTED_PROLOGUE, 3) != 0) {
            set_result(1,
                "ADVERTENCIA: el prologo de la funcion no coincide con el esperado\n"
                "(558bec vs %02x%02x%02x).\n\n"
                "Esta build de la DLL puede diferir de la analizada en el laboratorio.\n"
                "No se escribio nada (abortado por seguridad).",
                data[file_off], data[file_off+1], data[file_off+2]);
            printf("[!] %s\n", g_result);
            free(data); free(secs);
            goto show_and_exit;
        }
        patch_off = file_off;
        patch_bytes = STUB;
        patch_len = STUB_LEN;
        desc = "reemplazo de funcion completa";
    }

    FILE *btest = fopen(backup_path, "rb");
    if (btest) {
        fclose(btest);
        printf("[*] Backup ya existia en %s (no se sobreescribe)\n", backup_path);
    } else {
        if (copy_file(path, backup_path)) {
            printf("[+] Backup creado en %s\n", backup_path);
        } else {
            set_result(1, "No se pudo crear el backup del archivo original.\nAbortando por seguridad (no se escribio nada).");
            fprintf(stderr, "[!] %s\n", g_result);
            free(data); free(secs);
            goto show_and_exit;
        }
    }

    memcpy(data + patch_off, patch_bytes, patch_len);

    if (write_file(path, data, sz)) {
        printf("[+] Parche aplicado (%zu bytes, %s).\n", patch_len, desc);
        printf("    Nuevos bytes: ");
        for (size_t i = 0; i < patch_len; i++) printf("%02x", data[patch_off+i]);
        printf("\n");
        if (is_bypass) {
            set_result(0,
                "PARCHE APLICADO CORRECTAMENTE\n\n"
                "Archivo: %s\n"
                "Target:  %s (%s)\n"
                "Mecanismo: %s\n"
                "Offset:  +0x%x (file offset 0x%lx)\n"
                "Bytes modificados: %zu\n\n"
                "Backup del original en:\n%s\n\n"
                "Cerra y volve a abrir el programa para ver el efecto.\n"
                "Para revertir TODO, corre este mismo .exe con --restore.\n\n"
                "----------------------------------------\n"
                "PoC de auditoria de seguridad\n"
                "Dante Annetta, 2026",
                path, target_key, TARGET_EXPORT, desc, target->body_offset, patch_off, patch_len, backup_path);
        } else {
            set_result(0,
                "PARCHE APLICADO CORRECTAMENTE\n\n"
                "Archivo: %s\n"
                "Target:  %s (%s)\n"
                "Valor forzado: %ld (0x%lx)\n"
                "Offset:  0x%lx\n"
                "Bytes modificados: %zu\n\n"
                "Backup del original en:\n%s\n\n"
                "Cerra y volve a abrir el programa para ver el efecto.\n"
                "Para revertir TODO, corre este mismo .exe con --restore.\n\n"
                "----------------------------------------\n"
                "PoC de auditoria de seguridad\n"
                "Dante Annetta, 2026",
                path, target_key, TARGET_EXPORT, value, value, patch_off, patch_len, backup_path);
        }
    } else {
        set_result(1, "Fallo al escribir el archivo parcheado.");
        fprintf(stderr, "[!] %s\n", g_result);
    }

    free(data);
    free(secs);

show_and_exit:
    if (g_result[0]) {
        MessageBoxA(NULL, g_result,
                    g_is_error ? "patch_brick - ERROR" : "patch_brick - Completado",
                    MB_OK | (g_is_error ? MB_ICONERROR : MB_ICONINFORMATION));
    }
    printf("\nPresiona ENTER para salir...");
    getchar();
    return g_is_error ? 1 : 0;
}
