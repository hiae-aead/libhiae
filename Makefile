# HiAE Makefile
# High-Throughput Authenticated Encryption Algorithm

# Compiler and flags
CC = cc

# Detect architecture and set appropriate flags
ARCH := $(shell uname -m)

CFLAGS = -O3 -I include -Wall -Wextra
LDFLAGS = -lm

# Source files
# Runtime dispatch builds all implementations and selects at runtime
MAIN_SOURCE = src/hiae/HiAE.c src/hiaex2/HiAEx2.c
HEADERS = include/HiAE.h src/hiae/HiAE_internal.h

IMPL_SOURCES += src/hiae/HiAE_software.c src/hiae/HiAE_stream.c
IMPL_SOURCES += src/hiae/HiAE_aesni.c src/hiae/HiAE_vaes_avx512.c
IMPL_SOURCES += src/hiae/HiAE_arm.c src/hiae/HiAE_arm_sha3.c

IMPL_SOURCES += src/hiaex2/HiAEx2_stream.c
IMPL_SOURCES += src/hiaex2/HiAEx2_arm.c
IMPL_SOURCES += src/hiaex2/HiAEx2_arm_sha3.c
IMPL_SOURCES += src/hiaex2/HiAEx2_software.c
IMPL_SOURCES += src/hiaex2/HiAEx2_vaes_avx2.c

ALL_SOURCES = $(MAIN_SOURCE) $(IMPL_SOURCES)

# Output directory for binaries
BINDIR = bin

# Target executables
TARGETS = $(BINDIR)/perf_test $(BINDIR)/perf_x2_test $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/test_stream $(BINDIR)/hiae

# Default target
all: $(BINDIR) $(TARGETS)

# Create bin directory
$(BINDIR):
	@mkdir -p $(BINDIR)

# Performance test
$(BINDIR)/perf_test: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/performance_test.c
	@echo "Building performance test..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/performance_test.c -o $@ $(LDFLAGS)

# Performance x2 test
$(BINDIR)/perf_x2_test: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/performance_x2_test.c
	@echo "Building performance x2 test..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/performance_x2_test.c -o $@ $(LDFLAGS)

# Functional test
$(BINDIR)/func_test: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/function_test.c
	@echo "Building functional test..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/function_test.c -o $@ $(LDFLAGS)

# Test vectors validation
$(BINDIR)/test_vectors: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/test_vectors_ietf.c
	@echo "Building test vectors validation..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/test_vectors_ietf.c -o $@ $(LDFLAGS)

# Streaming API test
$(BINDIR)/test_stream: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/test_stream.c
	@echo "Building streaming API test..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/test_stream.c -o $@ $(LDFLAGS)

# HiAE CLI utility
$(BINDIR)/hiae: $(BINDIR) $(ALL_SOURCES) $(HEADERS) hiae-cli/src/hiae.c hiae-cli/src/key_utils.c hiae-cli/src/file_ops.c hiae-cli/src/platform.c
	@echo "Building hiae CLI utility..."
	$(CC) $(CFLAGS) -I hiae-cli/src $(ALL_SOURCES) hiae-cli/src/hiae.c hiae-cli/src/key_utils.c hiae-cli/src/file_ops.c hiae-cli/src/platform.c -o $@ $(LDFLAGS)

# Test targets
test: $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/test_stream
	@echo "Running functional tests..."
	./$(BINDIR)/func_test
	@echo ""
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors
	@echo ""
	@echo "Running streaming API tests..."
	./$(BINDIR)/test_stream

test-vectors: $(BINDIR)/test_vectors
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors

benchmark: $(BINDIR)/perf_test $(BINDIR)/perf_x2_test
	@echo "Running performance benchmark..."
	./$(BINDIR)/perf_x2_test
	./$(BINDIR)/perf_test

# Clean target
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BINDIR)

# Help target
help:
	@echo "HiAE Makefile targets:"
	@echo "  make all              - Build all targets (default)"
	@echo "  make test             - Build and run all tests"
	@echo "  make test-vectors     - Build and run test vector validation"
	@echo "  make benchmark        - Build and run performance benchmark"
	@echo "  make perf_test        - Build performance test only"
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
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Runtime dispatch automatically selects the best implementation based on CPU features."

# Individual target shortcuts
perf_test: $(BINDIR)/perf_test
perf_x2_test: $(BINDIR)/perf_x2_test
func_test: $(BINDIR)/func_test
test_vectors: $(BINDIR)/test_vectors
test_stream: $(BINDIR)/test_stream
hiae: $(BINDIR)/hiae

# Installation
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCDIR = $(PREFIX)/include

# Static library
$(BINDIR)/libhiae.a: $(BINDIR) $(ALL_SOURCES) $(HEADERS)
	@echo "Building static library..."
	$(CC) $(CFLAGS) -c $(ALL_SOURCES)
	ar rcs $@ *.o
	@rm -f *.o

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

# Phony targets
.PHONY: all test test-vectors benchmark clean help perf_test perf_x2_test func_test test_vectors test_stream hiae install uninstall libhiae format format-check
