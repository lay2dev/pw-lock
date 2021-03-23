TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -O3 -I deps/libecc/src -I deps/libecc/src/external_deps -I deps/ckb-c-std-lib/molecule -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g -DWORDSIZE=64  -DWITH_STDLIB -D__unix__ -DHAS_ETHEREUM -DHAS_EOS -DHAS_TRON -DHAS_BITCOIN -DHAS_DOGECOIN -DHAS_WEBAUTHN
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -DWITH_STDLIB -D__unix__ -DWORDSIZE=64
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
SECP256R1_DEP := deps/libecc/build/libsign.a
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: specs/cells/pw_anyone_can_pay specs/cells/secp256r1_sha256_sighash

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/pw_anyone_can_pay: c/pw_anyone_can_pay.c ${PROTOCOL_HEADER} c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC) $(SECP256R1_DEP)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(SECP256R1_DEP) deps/libecc/src/external_deps/rand.c  deps/libecc/src/external_deps/print.c -o $@
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/secp256r1_sha256_sighash: c/secp256r1_sha256_sighash.c $(SECP256R1_DEP)
	$(CC) $(CFLAGS) $(LDFLAGS)  $< $(SECP256R1_DEP) deps/libecc/src/external_deps/rand.c  deps/libecc/src/external_deps/print.c -o $@
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

$(SECP256R1_DEP):
	cd deps/libecc && \
	CC=$(CC) LD=$(LD) BLINDING=0 COMPLETE=0 make 64

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
	rm -rf specs/cells/pw_anyone_can_pay specs/cells/secp256r1_sha256_sighash
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
