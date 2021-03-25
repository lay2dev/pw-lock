TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps -I deps/ckb-c-stdlib/molecule -I c -I build -I deps/secp256k1/src -I deps/secp256k1 -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g -DHAS_ETHEREUM -DHAS_EOS -DHAS_TRON -DHAS_BITCOIN -DHAS_DOGECOIN -DHAS_EXTENDED_VALIDATOR
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections 
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
SECP256R1_DEP := deps/libecc/build/libsign.a

CFLAGS_MBEDTLS := -fPIC -Os -fno-builtin-printf -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/molecule -I deps/ckb-c-stdlib/libc -I deps/secp256k1/src -I deps/secp256k1 -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g -DWORDSIZE=64 -D__unix__ -DWITH_STDLIB

LDFLAGS_MBEDTLS := -Wl,-static -Wl,--gc-sections
PASSED_R1_CFLAGS := -Os -fPIC -nostdinc -nostdlib -DCKB_DECLARATION_ONLY -DWORDSIZE=64 -D__unix__ -DWITH_STDLIB  -fdata-sections -ffunction-sections -I ../ckb-c-stdlib/libc

CFLAGS_R1 := -fPIC -Os -fno-builtin-printf -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/libecc -I deps/libecc/src -I deps/libecc/src/external_deps -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/molecule -I deps/ckb-c-stdlib/libc -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g -DWORDSIZE=64 -D__unix__ -DWITH_STDLIB 

# CFLAGS_R1 := -fPIC -O3 -nostdinc -nostdlib -fvisibility=hidden -I deps/libecc -I deps/libecc/src -I deps/libecc/src/external_deps -I deps/ckb-c-stdlib  -I deps -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -I c -I build -I deps/secp256k1/src -I deps/secp256k1 -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g -DWORDSIZE=64 -D__unix__ -DWITH_STDLIB 
LDFLAGS_R1 := -Wl,-static -Wl,--gc-sections



MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

#all: specs/cells/pw_anyone_can_pay specs/cells/secp256r1_sha256_sighash
all: specs/cells/pw_anyone_can_pay specs/cells/pwlock_webauthn_lib

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/pw_anyone_can_pay: c/pw_anyone_can_pay.c ${PROTOCOL_HEADER} c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC) 
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< 
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

r1-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make specs/cells/secp256r1_sha256_sighash"


specs/cells/secp256r1_sha256_sighash: c/secp256r1_sha256_sighash.c  $(SECP256R1_DEP) 
	$(CC) $(CFLAGS_R1) $(LDFLAGS) $< $(SECP256R1_DEP) deps/libecc/src/external_deps/rand.c deps/libecc/src/external_deps/print.c  -o $@  
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

lib-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make build/pwlock_webauthn_lib"

specs/cells/pwlock_webauthn_lib: c/webauthn/pw_webauthn_lib.c $(SECP256R1_DEP)
	$(CC) $(CFLAGS_R1) $(LDFLAGS_R1) -D__SHARED_LIBRARY__ -fPIC -fPIE -pie -Wl,--dynamic-list c/webauthn/pw_webauthn.syms $< $(SECP256R1_DEP) deps/libecc/src/external_deps/rand.c deps/libecc/src/external_deps/print.c  -o $@ 
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/pwlock_sighash_all_lib: c/pwlock_sighash_all_lib.c build/secp256k1_data_info.h $(SECP256R1_DEP)
	$(CC) $(CFLAGS_R1) $(LDFLAGS)  -fPIC -fPIE -pie -Wl,--dynamic-list c/pwlock.syms $< $(SECP256R1_DEP) deps/libecc/src/external_deps/rand.c deps/libecc/src/external_deps/print.c  -o $@ 
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc -O3 -I deps/secp256k1/src -I deps/secp256k1 -o $@ $<


$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

$(SECP256R1_DEP):
	cd deps/libecc && \
	CC=$(CC) LD=$(LD) CFLAGS="${PASSED_R1_CFLAGS}" BLINDING=0 COMPLETE=0 make 64

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

publish:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo publish --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo package --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf ${PROTOCOL_HEADER} ${PROTOCOL_SCHEMA}
	rm -rf specs/cells/pw_anyone_can_pay specs/cells/secp256r1_sha256_sighash specs/cells/pwlock_webauthn_lib
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf specs/cells/secp256k1_data
	rm -rf build/*.debug
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean
	cd deps/libecc && make clean
	#cargo clean

fmt:
	clang-format -i -style=Google $(wildcard c/*.h c/*.c)
	# git diff --exit-code $(wildcard c/*.h c/*.c)

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
