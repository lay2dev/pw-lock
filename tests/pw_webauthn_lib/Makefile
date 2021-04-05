OS = Unknown
ifneq ($(shell uname -a | grep -i Darwin),)
	OS = MacOS
endif
ifneq ($(shell uname -a | grep -i Linux),)
	OS = Linux
endif
ifeq ($(OS),Unknown)
	echo "error: unsupported OS"; exit 1
endif

NPROC?=4
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

CORPUS_DIR=corpus
FLAGS=-I../../deps/libecc/src -I../../c -I. -DWORDSIZE=64 -DWITH_STDLIB -D__unix__ -DCKB_SIMULATOR -DNN_CONSISTENCY_CHECK -Wno-macro-redefined

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined $(FLAGS)

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping $(FLAGS)

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../c/webauthn/pw_webauthn.h

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata webauthn_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata webauthn_coverage $(EXTERNAL_HEADERS)

fuzzer:
	clang $(FUZZER_FLAGS) fuzzer.c -o webauthn_fuzzer
	
coverage: $(EXTERNAL_HEADERS)
	clang $(COVERAGE_FLAGS) coverage.c fuzzer.c -o webauthn_coverage

start-fuzzer: fuzzer
	./webauthn_fuzzer -workers=$(NPROC) -jobs=$(NPROC) -max_len=700 corpus

clean:
	rm -rf webauthn_fuzzer webauthn_coverage webauthn_fuzzer.dSYM

#%.h:export
#	ln -s $(CURDIR)/../$@ $(CURDIR)/$@

%.profraw: coverage
	echo "start webauthn_coverage"
	LLVM_PROFILE_FILE=$@ ./webauthn_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
