# Reproducible inventory fixtures. Run from repo root:
#   make -C testdata/inventory
#
# Binaries are committed under bin/ so CI on macOS/Windows can exercise
# ELF fixtures without a Linux cross-compiler. Rebuild on Linux when
# sources change.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRC  := $(ROOT)/src
BIN  := $(ROOT)/bin
CC   ?= gcc
CXX  ?= g++

.PHONY: all clean verify

all: \
	$(BIN)/dyn_unstripped_elf \
	$(BIN)/dyn_stripped_elf \
	$(BIN)/static_stripped_elf \
	$(BIN)/cxx_mangled_elf \
	$(BIN)/symver_ssl_elf \
	$(BIN)/symver_def.so \
	$(BIN)/weak_ifunc_elf \
	$(BIN)/sample_pe.exe \
	$(BIN)/sample_macho \
	$(BIN)/truncated_elf \
	$(BIN)/README.md

$(BIN):
	mkdir -p $(BIN)

$(BIN)/dyn_unstripped_elf: $(SRC)/dyn.c | $(BIN)
	$(CC) -O0 -g -o $@ $<

$(BIN)/dyn_stripped_elf: $(SRC)/dyn.c | $(BIN)
	$(CC) -O0 -s -o $@ $<

$(BIN)/static_stripped_elf: $(SRC)/dyn.c | $(BIN)
	$(CC) -O0 -static -s -o $@ $<

$(BIN)/cxx_mangled_elf: $(SRC)/cxx.cpp | $(BIN)
	$(CXX) -O0 -g -o $@ $<

$(BIN)/symver_ssl_elf: $(SRC)/sslver.c | $(BIN)
	$(CC) -O0 -g -o $@ $< $(shell pkg-config --libs libssl libcrypto 2>/dev/null || echo -lssl -lcrypto)

$(BIN)/symver_def.so: $(SRC)/vers.c $(SRC)/vers.map | $(BIN)
	$(CC) -shared -fPIC -Wl,--version-script=$(SRC)/vers.map -o $@ $(SRC)/vers.c

$(BIN)/weak_ifunc_elf: $(SRC)/weak_ifunc.c | $(BIN)
	$(CC) -O0 -g -o $@ $<

$(BIN)/sample_pe.exe: $(SRC)/gocross/main.go | $(BIN)
	cd $(SRC)/gocross && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN)/sample_pe.exe .

$(BIN)/sample_macho: $(SRC)/gocross/main.go | $(BIN)
	cd $(SRC)/gocross && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN)/sample_macho .

$(BIN)/truncated_elf: | $(BIN)
	# Valid ELF magic then truncated — must Warning, not panic.
	printf '\177ELF\x02\x01\x01\x00' > $@
	dd if=/dev/zero bs=1 count=24 >> $@ 2>/dev/null

$(BIN)/README.md: | $(BIN)
	@printf '%s\n' \
		'# Inventory fixtures' \
		'' \
		'Built by `make -C testdata/inventory`.' \
		'Do not hand-edit binaries; change sources and rebuild.' \
		> $@

clean:
	rm -rf $(BIN)

verify: all
	@command -v file >/dev/null && file $(BIN)/*_elf $(BIN)/sample_* || true
	@command -v readelf >/dev/null && \
		echo '--- dyn_stripped ---' && readelf -h $(BIN)/dyn_stripped_elf | head -5 && \
		echo '--- static_stripped ---' && readelf -h $(BIN)/static_stripped_elf | head -5 && \
		(readelf -d $(BIN)/static_stripped_elf 2>&1 | grep -E 'NEEDED|INTERP' || echo 'static: no NEEDED/INTERP') && \
		(readelf -S $(BIN)/dyn_stripped_elf | grep symtab || echo 'stripped: no .symtab') && \
		(readelf -S $(BIN)/dyn_unstripped_elf | grep symtab || true)
