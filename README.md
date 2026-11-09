# Auditoría de seguridad — TwidoSuite 2.3 (Schneider Electric)

Repositorio privado de trabajo para una auditoría de seguridad **autorizada** sobre el
sistema de registro/licenciamiento de TwidoSuite 2.3 (`RegistrationWizard.exe` /
`BrickLicenceManager.dll`, basado en SoftwareKey Protection Plus).

## Alcance y autorización

Trabajo realizado con autorización explícita del propietario del sistema evaluado. Todo el
contenido corresponde a análisis propio — **no incluye binarios del producto auditado**
(DLLs, ejecutables, instalador). Los MD5 de referencia (ver `docs/AUDIT_REPORT.md` §2)
permiten verificar/reproducir contra una copia legítima.

## Mapa del repositorio

| Ruta | Qué es |
|---|---|
| **`docs/`** | Toda la documentación de la auditoría |
| &nbsp;&nbsp;`docs/AUDIT_REPORT.md` | Informe principal: arquitectura, vectores, evidencia, offsets, hashes |
| &nbsp;&nbsp;`docs/UNIVERSAL_PATCH.md` | **Patch universal** (registrado en fresh + trial vencido) y el patcher |
| &nbsp;&nbsp;`docs/live-test-2026-11-09.md` | Prueba de ejecución en vivo (GUI) con DLL parcheada |
| &nbsp;&nbsp;`docs/INSTALL.md` | Guía de instalación del tooling por prueba |
| &nbsp;&nbsp;`docs/PENDING_WORK.md` | Trabajo pendiente, priorizado, con estado actualizado |
| &nbsp;&nbsp;`docs/evidence/` | Capturas y evidencia |
| **`tools/`** | Herramientas de análisis desarrolladas durante la auditoría |
| &nbsp;&nbsp;`tools/patcher/` | Parcheadores de `BrickLicenceManager.dll` (`patch_brick.c`, `twido_patch.c`) |
| &nbsp;&nbsp;`tools/harnesses/` | Llamadores directos a los exports de la DLL sin pasar por la GUI (`harness*.c`) |
| &nbsp;&nbsp;`tools/crypto/` | `pp_cipher.py` — reimplementación del cifrado propietario |
| **`vm_tooling/`** | Scripts de automatización QEMU/QMP (intento de entorno Windows nativo) |

> Carpetas locales **no versionadas** (gitignored): `wine_twido/` (prefix), `vendor_media/`
> (instalador extraído), `ghidra/`, `rea/`, `artifacts/`, y el `.zip` del producto.

## Resultados principales

1. **Vector de sesión** — `Hub_OpenSession` abre sesión válida con doble patch del gate
   challenge-response + los valores de producto correctos. Demo GET→SET→GET 100%
   programática (`tools/harnesses/harness4.c`).
2. **Producto registrado** — la GUI entra como registrado forzando el código de estado
   (`0xb`→`0xf`) que lee `Hub_GetActiveLicenseState`. Verificado en vivo.
3. **Patch universal** — stub de `pp_expired` + estado `0xf` ⇒ registrado tanto en
   instalación nueva como con **trial vencido**. Patcher dinámico `tools/patcher/twido_patch.c`.

Detalle completo en `docs/UNIVERSAL_PATCH.md` y `docs/AUDIT_REPORT.md`.

## Herramientas — build rápido

```bash
# patcher (recomendado): aplica el patch universal, backup + --restore
i686-w64-mingw32-gcc -O2 -o twido_patch.exe tools/patcher/twido_patch.c -lgdi32

# harness de demostración GET→SET→GET
i686-w64-mingw32-gcc -O0 -o harness4.exe tools/harnesses/harness4.c
```

Ver `docs/INSTALL.md` para el tooling de cada prueba (Wine+VB6, mingw, REA+Ghidra+JDK).

## Estado

Ver `docs/AUDIT_REPORT.md` §9 y `docs/PENDING_WORK.md` para los ítems abiertos.
