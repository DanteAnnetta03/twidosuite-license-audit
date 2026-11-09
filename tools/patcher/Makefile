# Makefile — construye los ejecutables del parche en dist/
#
#   Linux (cross-compile):   make           (usa i686-w64-mingw32-gcc)
#   Windows (MinGW-w64):     mingw32-make   (usa gcc)
#
# Resultado:  dist/twido_patch.exe  dist/twido_restore.exe  dist/README.md
# Empaquetado:  make package   ->  dist/twido-patch-tools.zip

DIST    := dist
CFLAGS  ?= -O2 -s
LDLIBS  := -lgdi32
PKG     := twido-patch-tools.zip
EXES    := $(DIST)/twido_patch.exe $(DIST)/twido_restore.exe

ifeq ($(OS),Windows_NT)
  # Windows + MinGW-w64: gcc genera PE nativo
  ifeq ($(origin CC),default)
    CC   := gcc
  endif
  MKDIR  = if not exist $(DIST) mkdir $(DIST)
  COPY   = copy /Y
  RMDIR  = if exist $(DIST) rmdir /S /Q $(DIST)
  FIXP   = $(subst /,\,$1)
else
  # Linux: cross-compiler a Windows de 32 bits
  ifeq ($(origin CC),default)
    CC   := i686-w64-mingw32-gcc
  endif
  MKDIR  = mkdir -p $(DIST)
  COPY   = cp -f
  RMDIR  = rm -rf $(DIST)
  FIXP   = $1
endif

.PHONY: all clean package
all: $(EXES) $(DIST)/README.md

$(DIST)/twido_patch.exe: twido_patch.c
	$(MKDIR)
	$(CC) $(CFLAGS) -o $(call FIXP,$@) $< $(LDLIBS)

$(DIST)/twido_restore.exe: twido_restore.c
	$(MKDIR)
	$(CC) $(CFLAGS) -o $(call FIXP,$@) $< $(LDLIBS)

$(DIST)/README.md: README.dist.md
	$(MKDIR)
	$(COPY) $(call FIXP,README.dist.md) $(call FIXP,$@)

# Empaqueta dist/ en un .zip (Linux: zip; Windows: PowerShell Compress-Archive)
package: all
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -Command "Compress-Archive -Force -Path '$(DIST)/twido_patch.exe','$(DIST)/twido_restore.exe','$(DIST)/README.md' -DestinationPath '$(DIST)/$(PKG)'"
else
	cd $(DIST) && zip -q -FS $(PKG) twido_patch.exe twido_restore.exe README.md
endif

clean:
	$(RMDIR)
