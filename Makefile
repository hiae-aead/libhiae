# HiAE Makefile
# High-Throughput Authenticated Encryption Algorithm

CC ?= cc
AR ?= ar
CFLAGS ?= -O3 -mtune=native -I include -Wall
LDFLAGS ?= -lm

# Detect architecture and set appropriate flags
ARCH := $(shell uname -m)

# Source files
# Runtime dispatch builds all implementations and selects at runtime
MAIN_SOURCE = src/hiae/HiAE.c src/hiaex2/HiAEx2.c src/hiaex4/HiAEx4.c src/hiaet/HiAEt.c

IMPL_SOURCES += src/hiae/HiAE_software.c src/hiae/HiAE_stream.c
IMPL_SOURCES += src/hiae/HiAE_aesni.c src/hiae/HiAE_vaes_avx512.c
IMPL_SOURCES += src/hiae/HiAE_arm.c src/hiae/HiAE_arm_sha3.c

IMPL_SOURCES += src/hiaex2/HiAEx2_stream.c
IMPL_SOURCES += src/hiaex2/HiAEx2_arm.c
IMPL_SOURCES += src/hiaex2/HiAEx2_arm_sha3.c
IMPL_SOURCES += src/hiaex2/HiAEx2_software.c
IMPL_SOURCES += src/hiaex2/HiAEx2_vaes_avx2.c
IMPL_SOURCES += src/hiaex2/HiAEx2_aesni_avx.c

IMPL_SOURCES += src/hiaex4/HiAEx4_stream.c
IMPL_SOURCES += src/hiaex4/HiAEx4_arm.c
IMPL_SOURCES += src/hiaex4/HiAEx4_arm_sha3.c
IMPL_SOURCES += src/hiaex4/HiAEx4_software.c
IMPL_SOURCES += src/hiaex4/HiAEx4_vaes_avx512.c

IMPL_SOURCES += src/hiaet/HiAEt_software.c
IMPL_SOURCES += src/hiaet/HiAEt_arm_sha3.c
IMPL_SOURCES += src/hiaet/HiAEt_aesni.c
IMPL_SOURCES += src/hiaet/HiAEt_vaes_avx512.c

ALL_SOURCES = $(MAIN_SOURCE) $(IMPL_SOURCES)

# Header dependencies
HIAE_HEADERS = include/HiAE.h src/hiae/HiAE_internal.h src/hiae/softaes.h
HIAEX2_HEADERS = include/HiAEx2.h src/hiaex2/HiAEx2_internal.h src/hiaex2/softaes.h
HIAEX4_HEADERS = include/HiAEx4.h src/hiaex4/HiAEx4_internal.h src/hiaex4/softaes.h
HIAET_HEADERS = include/HiAEt.h src/hiaet/HiAEt_internal.h src/hiaet/softaes.h
CLI_HEADERS = hiae-cli/src/platform.h hiae-cli/src/key_utils.h hiae-cli/src/file_ops.h
TEST_HEADERS = test/timing.h

# Object files
MAIN_OBJECTS = $(MAIN_SOURCE:%.c=$(BINDIR)/%.o)
IMPL_OBJECTS = $(IMPL_SOURCES:%.c=$(BINDIR)/%.o)
ALL_OBJECTS = $(MAIN_OBJECTS) $(IMPL_OBJECTS)

# Output directory for binaries
BINDIR = bin

# Target executables
TARGETS = $(BINDIR)/perf_test $(BINDIR)/perf_x2_test $(BINDIR)/perf_x4_test $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/test_vectors_hiaex2 $(BINDIR)/test_stream $(BINDIR)/hiae $(BINDIR)/hiaet_func_test $(BINDIR)/hiaet_perf_test

# Default target
all: $(BINDIR) $(TARGETS)

# Create bin directory and subdirectories for object files
$(BINDIR):
	@mkdir -p $(BINDIR)
	@mkdir -p $(BINDIR)/src/hiae
	@mkdir -p $(BINDIR)/src/hiaex2
	@mkdir -p $(BINDIR)/src/hiaex4
	@mkdir -p $(BINDIR)/src/hiaet

# Object file rules with proper header dependencies
$(BINDIR)/src/hiae/%.o: src/hiae/%.c $(HIAE_HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BINDIR)/src/hiaex2/%.o: src/hiaex2/%.c $(HIAEX2_HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BINDIR)/src/hiaex4/%.o: src/hiaex4/%.c $(HIAEX4_HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BINDIR)/src/hiaet/%.o: src/hiaet/%.c $(HIAET_HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Performance test
$(BINDIR)/perf_test: $(ALL_OBJECTS) test/performance_test.c $(TEST_HEADERS)
	@echo "Building performance test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/performance_test.c -o $@ $(LDFLAGS)

# Performance x2 test
$(BINDIR)/perf_x2_test: $(ALL_OBJECTS) test/performance_x2_test.c $(TEST_HEADERS)
	@echo "Building performance x2 test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/performance_x2_test.c -o $@ $(LDFLAGS)

# Performance x4 test
$(BINDIR)/perf_x4_test: $(ALL_OBJECTS) test/performance_x4_test.c $(TEST_HEADERS)
	@echo "Building performance x4 test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/performance_x4_test.c -o $@ $(LDFLAGS)

# Functional test
$(BINDIR)/func_test: $(ALL_OBJECTS) test/function_test.c $(TEST_HEADERS)
	@echo "Building functional test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/function_test.c -o $@ $(LDFLAGS)

# Test vectors validation
$(BINDIR)/test_vectors: $(ALL_OBJECTS) test/test_vectors_ietf.c $(TEST_HEADERS)
	@echo "Building test vectors validation..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/test_vectors_ietf.c -o $@ $(LDFLAGS)

# HiAEx2 test vectors validation
$(BINDIR)/test_vectors_hiaex2: $(ALL_OBJECTS) test/test_vectors_hiaex2.c $(TEST_HEADERS)
	@echo "Building HiAEx2 test vectors validation..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/test_vectors_hiaex2.c -o $@ $(LDFLAGS)

# Streaming API test
$(BINDIR)/test_stream: $(ALL_OBJECTS) test/test_stream.c $(TEST_HEADERS)
	@echo "Building streaming API test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/test_stream.c -o $@ $(LDFLAGS)

# HiAE CLI utility
$(BINDIR)/hiae: $(ALL_OBJECTS) hiae-cli/src/hiae.c hiae-cli/src/key_utils.c hiae-cli/src/file_ops.c hiae-cli/src/platform.c $(CLI_HEADERS)
	@echo "Building hiae CLI utility..."
	$(CC) $(CFLAGS) -I hiae-cli/src $(ALL_OBJECTS) hiae-cli/src/hiae.c hiae-cli/src/key_utils.c hiae-cli/src/file_ops.c hiae-cli/src/platform.c -o $@ $(LDFLAGS)

# HiAEt functional test
$(BINDIR)/hiaet_func_test: $(ALL_OBJECTS) test/hiaet_function_test.c $(TEST_HEADERS)
	@echo "Building HiAEt functional test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/hiaet_function_test.c -o $@ $(LDFLAGS)

# HiAEt performance test
$(BINDIR)/hiaet_perf_test: $(ALL_OBJECTS) test/hiaet_performance_test.c $(TEST_HEADERS)
	@echo "Building HiAEt performance test..."
	$(CC) $(CFLAGS) $(ALL_OBJECTS) test/hiaet_performance_test.c -o $@ $(LDFLAGS)

# Test targets
test: $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/test_vectors_hiaex2 $(BINDIR)/test_stream $(BINDIR)/hiaet_func_test test-amalgamated
	@echo "Running functional tests..."
	./$(BINDIR)/func_test
	@echo ""
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors
	@echo ""
	@echo "Running HiAEx2 test vectors..."
	./$(BINDIR)/test_vectors_hiaex2
	@echo ""
	@echo "Running streaming API tests..."
	./$(BINDIR)/test_stream
	@echo ""
	@echo "Running HiAEt functional tests..."
	./$(BINDIR)/hiaet_func_test

test-vectors: $(BINDIR)/test_vectors
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors

benchmark: $(BINDIR)/perf_test $(BINDIR)/perf_x2_test $(BINDIR)/perf_x4_test $(BINDIR)/hiaet_perf_test
	@echo "Running performance benchmark..."
	./$(BINDIR)/perf_x4_test
	./$(BINDIR)/perf_x2_test
	./$(BINDIR)/perf_test
	@echo ""
	@echo "Running HiAEt performance benchmark..."
	./$(BINDIR)/hiaet_perf_test

hiaet-benchmark: $(BINDIR)/hiaet_perf_test
	@echo "Running HiAEt performance benchmark..."
	./$(BINDIR)/hiaet_perf_test

# Clean target
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BINDIR)

# Amalgamate target - creates single-file version
amalgamate:
	@echo "Creating amalgamated single-file version..."
	@if [ ! -d scripts ]; then mkdir -p scripts; fi
	@python3 scripts/amalgamate.py
	@echo "Amalgamated file created: HiAE_amalgamated.c"

# Help target
help:
	@echo "HiAE Makefile targets:"
	@echo "  make all              - Build all targets (default)"
	@echo "  make test             - Build and run all tests"
	@echo "  make test-vectors     - Build and run test vector validation"
	@echo "  make benchmark        - Build and run performance benchmark"
	@echo "  make perf_test        - Build performance test only"
	@echo "  make perf_x2_test     - Build HiAEx2 performance test only"
	@echo "  make perf_x4_test     - Build HiAEx4 performance test only"
	@echo "  make func_test        - Build functional test only"
	@echo "  make test_vectors     - Build test vectors validation only"
	@echo "  make test_stream      - Build streaming API test only"
	@echo "  make hiae             - Build hiae CLI utility only"
	@echo "  make libhiae          - Build static library only"
	@echo "  make install          - Install library and headers"
	@echo "  make uninstall        - Remove installed files"
	@echo "  make format           - Format code with clang-format"
	@echo "  make format-check     - Check code formatting"
	@echo "  make clean            - Remove all build artifacts"
	@echo "  make amalgamate       - Generate single-file amalgamated version"
	@echo "  make test-amalgamated - Test amalgamated version build and functionality"
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Runtime dispatch automatically selects the best implementation based on CPU features."

# Individual target shortcuts
perf_test: $(BINDIR)/perf_test
perf_x2_test: $(BINDIR)/perf_x2_test
perf_x4_test: $(BINDIR)/perf_x4_test
func_test: $(BINDIR)/func_test
test_vectors: $(BINDIR)/test_vectors
test_stream: $(BINDIR)/test_stream
hiae: $(BINDIR)/hiae

# Installation
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCDIR = $(PREFIX)/include

# Static library
$(BINDIR)/libhiae.a: $(ALL_OBJECTS)
	@echo "Building static library..."
	$(AR) rcs $@ $(ALL_OBJECTS)

# Install target
install: $(BINDIR)/libhiae.a
	@echo "Installing library and headers..."
	install -d $(LIBDIR) $(INCDIR)
	install -m 644 $(BINDIR)/libhiae.a $(LIBDIR)/
	install -m 644 include/HiAE.h $(INCDIR)/

# Uninstall target
uninstall:
	@echo "Uninstalling library and headers..."
	rm -f $(LIBDIR)/libhiae.a
	rm -f $(INCDIR)/HiAE.h

# Static library shortcut
libhiae: $(BINDIR)/libhiae.a

# Code formatting targets
format-check:
	@echo "Checking code formatting..."
	@if command -v clang-format >/dev/null 2>&1; then \
		find . -name "*.c" -o -name "*.h" | grep -v build | xargs clang-format --dry-run --Werror; \
	else \
		echo "clang-format not found, skipping format check"; \
	fi

format:
	@echo "Formatting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		find . -name "*.c" -o -name "*.h" | grep -v build | xargs clang-format -i; \
	else \
		echo "clang-format not found, cannot format code"; \
	fi

# Amalgamated version test
test-amalgamated: HiAE_amalgamated.c
	@echo "Testing amalgamated version..."
	@echo "Building test with amalgamated file..."
	$(CC) $(CFLAGS) -o $(BINDIR)/test_amalgamated test/test_amalgamated.c
	@echo "Running amalgamated version test..."
	./$(BINDIR)/test_amalgamated

# Phony targets
.PHONY: all test test-vectors benchmark clean help perf_test perf_x2_test perf_x4_test func_test test_vectors test_stream hiae install uninstall libhiae format format-check test-amalgamated
