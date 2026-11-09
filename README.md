# Auditoría de seguridad — TwidoSuite 2.3 (Schneider Electric)

Repositorio privado de trabajo para una auditoría de seguridad **autorizada** sobre el sistema de registro/licenciamiento de TwidoSuite 2.3 (`RegistrationWizard.exe` / `BrickLicenceManager.dll`, basado en SoftwareKey Protection Plus).

## Alcance y autorización

Este trabajo fue realizado con autorización explícita del propietario del sistema evaluado. Todo el contenido de este repositorio (hallazgos, herramientas, notas) corresponde a análisis propio — **no incluye binarios del producto auditado** (DLLs, ejecutables, instalador). Ver `AUDIT_REPORT.md` §2 para hashes de referencia que permiten verificar/reproducir el trabajo contra una copia legítima del producto.

## Contenido

| Archivo / carpeta | Descripción |
|---|---|
| [`AUDIT_REPORT.md`](AUDIT_REPORT.md) | Informe completo: arquitectura del sistema de licenciamiento, los tres vectores de ataque identificados, evidencia empírica, direcciones/offsets, hashes. |
| [`PENDING_WORK.md`](PENDING_WORK.md) | Trabajo pendiente, priorizado, con pasos concretos para retomar cada ítem. |
| `tools/` | Herramientas de análisis desarrolladas durante la auditoría (código fuente, C y Python). |
| `vm_tooling/` | Scripts de automatización de QEMU/QMP usados durante el intento de entorno Windows nativo (captura de pantalla, inyección de teclas, timeline de arranque). |

### `tools/`

- **`patch_brick.c`** — parcheador binario de `BrickLicenceManager.dll`. Localiza las funciones dinámicamente vía la tabla de exports del PE (no usa offsets fijos), verifica el patrón de bytes esperado antes de escribir, hace backup automático. Soporta 4 targets (`license`, `trial`, `expiration`, `opensession`), cada uno con el mecanismo de parche más seguro para ese caso (ver comentario de cabecera del archivo para el razonamiento completo).
  Build: `i686-w64-mingw32-gcc -O2 -o patch_brick.exe patch_brick.c -lgdi32`
- **`pp_cipher.py`** — reimplementación en Python del cifrado simétrico propietario de `BrickLicenceManager.dll` (reversado por análisis estático con radare2), validada con test de round-trip.
- **`harness.c`** — llama directo a `Hub_OpenSession` / `Hub_GetActiveLicenseState` sin pasar por la GUI VB6.
- **`harness2.c`** — extrae la password/seed real del cifrado vía `Rules_GetPassword` / `Rules_GetTSeed`.
- **`harness3.c`** — prueba `Hub_OpenSession` con firma de 5 argumentos; base para la demostración empírica del parche sobre el gate de sesión (ver informe §4.2).

Build de los harnesses: `i686-w64-mingw32-gcc -O0 -o harness.exe harness.c` (idem para los demás).

### `vm_tooling/`

Scripts Python que hablan el protocolo QMP de QEMU directamente (sin dependencias más allá de la librería estándar) para controlar una VM de forma scripteada cuando las herramientas GUI (`virt-manager`, captura de pantalla estándar) no eran confiables en el entorno de prueba:

- **`qmp_lib.py`** — cliente QMP mínimo reutilizable (conexión con reintentos, `send-key`, `screendump`).
- **`qmp_screendump.py`** / **`qmp_timeline.py`** — captura de pantalla puntual / en serie, para diagnosticar visualmente el proceso de arranque de la VM sin depender de captura de pantalla del host (que no funcionaba en el sandbox usado).
- **`qmp_keyspam.py`** — inyección de teclas en ráfaga vía QMP, usado al diagnosticar el prompt "press any key to boot" del firmware.

## Estado

Ver `AUDIT_REPORT.md` §9 (Conclusión) para la respuesta a la pregunta de auditoría, y `PENDING_WORK.md` para los ítems abiertos.
