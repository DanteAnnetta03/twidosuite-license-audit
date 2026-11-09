# Trabajo pendiente — Auditoría TwidoSuite 2.3

Continuación de `AUDIT_REPORT.md`. Items ordenados por qué tan cerca están de estar resueltos.

---

## 1. Completar la reconstrucción de sesión de `Hub_OpenSession`

**Estado:** muy avanzado, falta el último paso.

Sabemos (vía `Registration_Log.txt` del propio producto):
- La sesión real abre con `Product Name = "TwidoSuite"`, `Version = "02.50"` (valores de `RegistrationWizard.ini`, sección `[product]`: `RegistryName` / `RegistryVersion`).
- `Hub_OpenSession(p1, p2, p3, p4, p5_out)` tiene un gate de challenge-response: `strcmp(F(p1,p2,p3), p4)`. Parcheado (1 byte, offset `0x11809`: `74`→`EB`) cambia el HRESULT de `E_ACCESSDENIED` a no-error, pero el handle de sesión salió NULL con argumentos de prueba incorrectos (`"TWDBTFU10ES"` como p1).

**Siguiente paso concreto:** reintentar `harness3.exe` con `p1="TwidoSuite"`, `p2="02.50"` **y** la DLL parcheada (gate bypaseado), para ver si `session->Init()` (en `0x10038858`) ahora acepta estos valores correctos y devuelve un handle no-nulo. Si funciona, el camino queda abierto para:
- `Hub_GetActiveLicenseState` / `Hub_GetActiveTrialInfo` → leer el estado real.
- `Hub_SetLicenseFileFlag` / `Hub_SetActiveExpirationPolicy` → escribir estado "registrado".
- Releer para confirmar → demo GET→SET→GET completa, 100% programática (sin depender del GUI invisible).

Comando de referencia (desde `Registration/` en el Wine prefix, con `BrickLicenceManager.dll` ya parcheada):
```
wine harness3.exe "TwidoSuite" "02.50" 0 ""
```

---

## 2. Fórmula exacta del checksum MD5 por sección en `RegistrationWizard.ini`

**Estado:** confirmado que es MD5 forjable (constantes MD5 presentes en el binario), pero no se reprodujo el valor exacto.

Target conocido: sección `[product]`, `key=375b0b6a5ee43ff469953d88bfebae5d`. Se probaron ~20 formulaciones simples (distintos separadores, con/sin header, solo valores, solo pares clave=valor, con salts obvios) sin match.

**Próximos intentos sugeridos:**
- Capturar dinámicamente la llamada a la función MD5 dentro de `BrickLicenceManager.dll` (vía `headless.exe`, que ya probamos que funciona para depurar binarios propios/harnesses bajo Wine) cuando `RegistrationWizard.exe` valida el ini al arrancar — leer el buffer de entrada exacto antes del hash, en vez de seguir adivinando formulaciones offline.
- Alternativa: localizar en el desensamblado la rutina que arma el buffer antes de llamar a MD5 (buscar xrefs a las constantes `0x67452301` etc. en `BrickLicenceManager.dll`).

---

## 3. Extracción de semillas del EZ Trigger Code (`TriggerCodeSeed`, `RegKey2Seed`)

**Estado:** algoritmo identificado (local, basado en MD5 del registro CSV de `Hub_EvalutateTriggerCodes`), semillas no extraídas.

Las semillas se pasan desde `RegistrationWizard.exe`, que es **VB6 p-code** (no desensamblable con herramientas x86 estándar). Opciones no exploradas:
- Decompilador de p-code VB6 (ej. VB Decompiler / P32Dasm) — típicamente herramientas Windows GUI; bajo Wine en esta máquina probablemente tendrían el mismo problema de ventanas invisibles que bloqueó la demo visual (ver `AUDIT_REPORT.md` §7). Evaluar si alguna tiene modo línea de comandos.
- Observación dinámica: una vez resuelto el bloqueo de visibilidad de GUI (item 5), interceptar la llamada real a `Hub_EvalutateTriggerCodes` con un breakpoint y volcar los 9 argumentos — ahí están las semillas en claro.

---

## 4. Arranque de la VM Windows 11 (QEMU/OVMF)

**Estado:** diagnosticado a fondo, parcialmente resuelto, no completado.

- Causa raíz del timeout original: confirmada (timeout fijo ATA/ATAPI de OVMF, independiente del bus, probado A/B contra ISO pequeña).
- Workaround (imagen de instalador FAT32+GPT construida con `mtools`/`parted`, sin root) avanzó más que nunca: pasa el firmware, llega a cargar `bootmgfw.efi`.
- Quedó sin resolver: fallo en la ejecución de `bootmgfw.efi` bajo `q35` (se probó `virtio` para el disco — con problemas conocidos de compatibilidad con el boot manager de Windows — y `sata`, sin diferencia clara identificada; no se completó el diagnóstico del fallo específico ahí).

**Valor de resolver esto:** entorno Windows nativo, snapshoteable, con `x64dbg` real (no Wine) — eliminaría de raíz el problema de GUI invisible y permitiría la demo visual completa que motivó todo este camino.

---

## 5. GUI de Wine invisible (causa raíz no encontrada)

**Estado:** confirmado el síntoma, no la causa.

Ventanas de `RegistrationWizard.exe` lanzadas por Claude no son visibles ni por el usuario ni por captura de pantalla automatizada — ni siquiera usando `wine explorer /desktop=...` (modo que normalmente resuelve este tipo de problema). No se investigó: compositor de la sesión gráfica, diferencias entre lanzar vía shell vs. launcher de escritorio, permisos de la superficie gráfica.

**Nota:** esto es un problema de *este sandbox específico*, no del producto auditado — ver `project_env_constraints` en memoria de Claude para más contexto si se retoma en otra sesión.

---

## Resumen de prioridad sugerida

1. **Item 1** (sesión) — el más cercano a completarse, desbloquea la demo GET→SET→GET sin necesitar GUI ni VM.
2. **Item 3** (semillas) — depende de resolver visibilidad de GUI (item 5) o conseguir un decompilador VB6 que funcione.
3. **Item 4** (VM) — el camino "correcto" a largo plazo (Windows nativo), pero ya consumió mucho tiempo con retornos decrecientes.
4. **Items 2 y 5** — de menor prioridad para responder la pregunta de auditoría (ya respondida), útiles para completar el detalle técnico.
