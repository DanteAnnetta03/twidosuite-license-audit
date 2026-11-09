# Guía de instalación del tooling

Tooling necesario para reproducir cada prueba de la auditoría. Probado en Ubuntu
24.04 (Linux). Comandos con `sudo` los corre el operador.

## Resumen por prueba

| Prueba | Tooling requerido |
|---|---|
| Instalar y ejecutar TwidoSuite bajo Wine | Wine, winetricks (`vb6run`) |
| Compilar harnesses y el patcher (`.exe`) | `gcc-mingw-w64-i686` |
| Análisis estático / decompilación con Ghidra | Node 24.22.1+, REA, JDK 25, Ghidra 12.2 |
| Simular trial vencido | (ninguno extra — se fuerza `pp_expired`; ver nota faketime) |
| Automatización de VM (opcional, item 4) | QEMU/OVMF + scripts en `vm_tooling/` |

---

## 1. Wine + runtime VB6 (ejecutar TwidoSuite)

TwidoSuite 2.3 es una app VB6 → necesita `msvbvm60.dll` registrado.

```bash
sudo apt install -y wine winetricks
# prefix dedicado de 32 bits
export WINEPREFIX="$PWD/wine_twido" WINEARCH=win32
WINEDLLOVERRIDES="mscoree,mshtml=d" wineboot --init
# runtime VB6 (descarga el VB6 SP6 oficial de Microsoft)
winetricks -q vb6run
```

Instalación del producto (desde el instalador InstallShield extraído):

```bash
cd "<media>/Twidosuite v2.3/Eng-Spa"
WINEPREFIX="$PWD/wine_twido" WINEARCH=win32 DISPLAY=:0 wine setup.exe
```

Launcher del Navigator: `AS_DC31_Navigator.exe` (en la carpeta de instalación).

## 2. Cross-compiler mingw (construir los `.exe`)

Para `tools/harnesses/*.c` y `tools/patcher/*.c` (PE 32-bit):

```bash
sudo apt install -y gcc-mingw-w64-i686
# ejemplos
i686-w64-mingw32-gcc -O0 -o harness4.exe  tools/harnesses/harness4.c
i686-w64-mingw32-gcc -O2 -o twido_patch.exe tools/patcher/twido_patch.c -lgdi32
```

## 3. REA + Ghidra + JDK (decompilación / análisis estático)

### 3.1 Node.js 24.22.1+ (REA lo exige)

```bash
# via nvm
nvm install 24          # trae 24.22.x (el 24.20 del sistema NO alcanza)
nvm use 24
```

### 3.2 REA (reverse-engineer-anything, MCP)

```bash
cd rea/                 # checkout de morluto/rea
npm ci
npm install-scripts approve esbuild
npm run build:cached
node scripts/rea.mjs doctor      # chequeo
# registrar el MCP en Claude Code:
node scripts/rea.mjs setup --client claude_code --yes
```

### 3.3 Ghidra 12.2 + JDK 25

Ghidra 12.2 exige **JDK 25** (`application.java.min=25`), no 21.

```bash
# JDK 25 (Temurin) — local, sin tocar el Java del sistema
wget "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz" -O jdk25.tar.gz
tar xzf jdk25.tar.gz -C ghidra/jdk/

# Ghidra 12.2
wget "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip" -O ghidra.zip
unzip ghidra.zip -d ghidra/
# apuntar Ghidra al JDK 25 local
echo "JAVA_HOME_OVERRIDE=$PWD/ghidra/jdk/jdk-25.0.5+8" >> ghidra/ghidra_12.2_PUBLIC/support/launch.properties
```

Enganchar Ghidra a REA: agregar al server `rea` en `~/.claude.json` el bloque `env`
(REA lee estas variables al **arrancar** — reiniciar Claude Code después):

```json
"env": {
  "GHIDRA_INSTALL_DIR": "<repo>/ghidra/ghidra_12.2_PUBLIC",
  "JAVA_HOME": "<repo>/ghidra/jdk/jdk-25.0.5+8"
}
```

Verificar: `binary_session` debe mostrar el provider `ghidra` como `available`.

## 4. Simular trial vencido

Wine lee la hora con **syscalls directas**, por lo que `faketime`/`libfaketime`
(LD_PRELOAD) **no** afecta su reloj — no sirve para expirar el trial.

Método usado: forzar `pp_expired` a devolver `1` (expirado) con un patch temporal
(`MOV EAX,1; RET 4` = `B8 01 00 00 00 C2 04 00` en su entry `0x42f50`). El motor
registra entonces `License is expired` en `Registration_Log.txt`. Es un proxy
determinista de la expiración por fecha (cuya date-math ya está decompilada).

## 5. VM nativa (opcional — `vm_tooling/`, item 4 pendiente)

QEMU/OVMF + los scripts QMP de `vm_tooling/` (clientes mínimos sin dependencias más
allá de la stdlib). El arranque de la VM Windows 11 quedó pendiente; ver
`PENDING_WORK.md`.
