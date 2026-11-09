# Patch universal de licenciamiento — `BrickLicenceManager.dll`

Documenta el resultado principal de la fase de ejecución/decompilación (2026-11-09):
un **patch universal** de 2 cambios sobre `BrickLicenceManager.dll` que hace que
TwidoSuite 2.3 **entre como producto registrado**, tanto en una instalación nueva
(trial vigente) como con el **período de prueba vencido**. Todo el análisis se hizo
con Ghidra 12.2 (vía REA) y validación empírica bajo Wine.

> Alcance: auditoría autorizada. No se incluyen binarios del producto. Los MD5 de
> referencia permiten reproducir/verificar contra una copia legítima.

## 1. Arquitectura del chequeo (confirmada por decompilación)

`BrickLicenceManager.dll` es la capa "Hub" (wrapper TwidoSuite) sobre el SDK
**SoftwareKey Protection Plus** (exports `pp_*`). La GUI (`AS_DC31_Navigator.exe`)
decide "registrado / trial / vencido" a partir del **código de estado** que
devuelve `Hub_GetActiveLicenseState`.

Cadena relevante:

```
Hub_GetActiveLicenseState (export 0x10012d03)
  └─ FUN_1002d616  (ruta "sin archivo de licencia"; la licencia de Twido vive en
                    el registro RLM, por eso entra acá)
       ├─ lee el TIPO de expiración (FUN_10039c3f):
       │    1=LS_EXECUTION_COUNT · 2=LS_DEMO · 5=LS_PERIODIC · 6=LS_SHAREWARE · 0x10=LS_NONE
       ├─ IsExpired()  = FUN_1002d27d  →  llama a  pp_expired (export 0x10042f50)
       └─ escribe en *param_1 el CÓDIGO DE ESTADO que la GUI interpreta:
            0xa=sin política · 0xb=LS_DEMO activo(trial) · 0xd=intermedio
            0xe=expirado     · 0xf=permanente/registrado
```

- Estado real de la instalación: **`LS_DEMO` → estado `0xb`** ("no registrado, 90 días").
- `pp_expired` devuelve **`1`=expirado**, `0`=vigente, `0x1a/0x1b/0x1c`=error. Es el
  **único primitivo** por el que pasan TODAS las decisiones de expiración
  (confirmado: forzarlo a `1` → el log del motor escribe `License is expired`).

## 2. Los dos cambios del patch universal

| # | Función | VA / file offset | Bytes | Efecto |
|---|---|---|---|---|
| **U1** | `pp_expired` (entry) | `0x10042f50` / `0x42f50` | `55 8B EC 81 EC…` → `31 C0 C2 04 00` (`XOR EAX,EAX; RET 4`) | **nunca expirado** |
| **U2** | `FUN_1002d616` (estado LS_DEMO) | `0x1002d80b` / `0x2d80b` | `0B` → `0F` | **reporta estado `0xf` (registrado)** |

- `pp_expired` es `__stdcall` con 1 argumento → el stub termina en `RET 4`.
- U2 cambia el inmediato de `MOV dword ptr [EDX], 0x0B` por `0x0F`. Patrón único de
  14 bytes que lo distingue del caso `LS_PERIODIC`:
  `8B 55 08 C7 02 0B 00 00 00 E9 27 01 00 00`.

**Por qué es universal:** U1 elimina por completo el chequeo de fecha (stubbea el
único primitivo de expiración), así que fresh y vencido se comportan idéntico; U2
fuerza el estado a "registrado". No queda ninguna condición dependiente de la fecha.

### MD5 de referencia

| Artefacto | MD5 |
|---|---|
| original | `ce12439b39dfcb0d7b3451c18d63edf4` |
| universal (U1+U2) | `4f85ece5b3dafb631e45928726900d2c` |

## 3. Validación empírica (bajo Wine)

| Escenario | Cómo se reprodujo | Resultado |
|---|---|---|
| Fresh (trial vigente) | instalación normal | sin patch: "no registrado, 90 días" → con patch: **registrado** |
| Trial **vencido** | `pp_expired` forzado a `1` (determinista; Wine ignora `faketime`) | sin patch: log `License is expired` → con patch universal: **registrado** |

> Nota: Wine lee la hora por syscalls directas, así que `faketime`/`libfaketime`
> **no** afecta su reloj. La expiración se reprodujo forzando el valor de retorno de
> `pp_expired` (su date-math ya estaba decompilada), que es un proxy fiel del
> "la fecha concluyó vencido".

## 4. Los ejecutables: `tools/patcher/`

Dos programas pensados para que los usuarios de prueba los corran en **Windows nativo**.
Se colocan en la **carpeta principal de TwidoSuite** (buscan la DLL en
`.\Registration\BrickLicenceManager.dll`, relativa al `.exe`):

| Ejecutable (fuente) | Función |
|---|---|
| `twido_patch.c` → `twido_patch.exe` | Aplica U1+U2. Backup automático (`<dll>.orig_backup`), idempotente. |
| `twido_restore.c` → `twido_restore.exe` | Restaura la DLL original desde el backup (reparación). |

Características:

- Localizan los sitios **dinámicamente** (no por offset fijo): `pp_expired` por la
  tabla de exports del PE; el estado por el patrón único de 14 bytes.
- Verifican los bytes esperados antes de escribir; abortan si no coinciden o si el
  patrón es ambiguo, con un mensaje que dice exactamente qué pasó.
- `MessageBox`: en éxito muestra solo `Done.` (con el autor); en error, el detalle exacto.

Build con `make` (genera `dist/` con los 2 exes + README, y un `.zip` con
`make package`). Linux (cross-compile) y Windows nativo (MinGW-w64) — ver `INSTALL.md`.

Validado: `twido_patch.exe` produce la DLL `4f85ece5…` (idéntica a la construida a
mano, la que entra registrada), es idempotente; `twido_restore.exe` devuelve el
original `ce12439b…`.

## 5. Alternativa considerada — patch en dos etapas

En vez del stub de `pp_expired`, se evaluó **(1)** resetear la cuenta regresiva del
trial (reescribir la fecha de inicio en los datos cifrados `Brk1License.dat`/registro
RLM) y **(2)** aplicar solo U2. Respeta la lógica de expiración pero exige
descifrar/recalcular con `pp_cipher.py` — más frágil. Se optó por el patch universal
por ser autocontenido y validado.
