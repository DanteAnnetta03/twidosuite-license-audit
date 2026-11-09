# TwidoSuite — herramientas de parche de licencia

Dos ejecutables para la prueba de licenciamiento de **TwidoSuite 2.3**:

| Ejecutable | Qué hace |
|---|---|
| **`twido_patch.exe`** | Aplica el parche: el producto entra **registrado** (instalación nueva o período de prueba vencido). Crea un backup de la DLL original la primera vez. |
| **`twido_restore.exe`** | **Repara**: restaura la DLL original desde el backup. Úsalo si algo sale mal o para dejar todo como estaba. |

> Uso autorizado de auditoría/prueba únicamente.

## Instalación

Copiá **ambos ejecutables** a la carpeta **principal de TwidoSuite**, por ejemplo:

```
C:\Program Files\Schneider Electric\TwidoSuite\
```

Esa carpeta es la que contiene la subcarpeta `Registration\` (donde vive
`BrickLicenceManager.dll`). Los ejecutables la encuentran solos.

## Uso

1. **Cerrá TwidoSuite** por completo.
2. Click derecho sobre `twido_patch.exe` → **Ejecutar como administrador**
   (necesita permiso para escribir en `Program Files`).
3. Aparece **"Done."** → listo. Abrí TwidoSuite: figura registrado.

Para revertir:

1. Cerrá TwidoSuite.
2. Ejecutá **`twido_restore.exe`** como administrador → **"Done."**
   (deja la DLL exactamente como estaba).

### Opcional — ruta explícita

Si TwidoSuite está instalado en otra ubicación, podés pasar la ruta de la DLL:

```
twido_patch.exe   "D:\ruta\TwidoSuite\Registration\BrickLicenceManager.dll"
twido_restore.exe "D:\ruta\TwidoSuite\Registration\BrickLicenceManager.dll"
```

## Notas

- El patch es **idempotente**: correr `twido_patch.exe` dos veces no rompe nada.
- Verifica los bytes esperados antes de escribir; si la DLL no es la versión
  soportada (TwidoSuite 2.3), **no toca nada** y el mensaje de error dice por qué.
- Backup automático: `BrickLicenceManager.dll.orig_backup` en `Registration\`.

— Dante Annetta
