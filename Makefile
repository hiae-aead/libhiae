# HiAE Makefile
# High-Throughput Authenticated Encryption Algorithm

# Compiler and flags
CC = cc -Wall -Wextra

# Detect architecture and set appropriate flags
ARCH := $(shell uname -m)

CFLAGS = -O3 -I include
LDFLAGS = 

# Source files
# Runtime dispatch builds all implementations and selects at runtime
MAIN_SOURCE = lib/HiAE.c
HEADERS = include/HiAE.h lib/HiAE_internal.h

IMPL_SOURCES = lib/HiAE_software.c lib/HiAE_stream.c
IMPL_SOURCES += lib/HiAE_aesni.c lib/HiAE_vaes_avx512.c
IMPL_SOURCES += lib/HiAE_arm.c lib/HiAE_arm_sha3.c

ALL_SOURCES = $(MAIN_SOURCE) $(IMPL_SOURCES)

# Output directory for binaries
BINDIR = bin

# Target executables
TARGETS = $(BINDIR)/perf_test $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/test_stream

# Default target
all: $(BINDIR) $(TARGETS)

# Create bin directory
$(BINDIR):
	@mkdir -p $(BINDIR)

# Performance test
$(BINDIR)/perf_test: $(BINDIR) $(ALL_SOURCES) $(HEADERS) test/performance_test.c
	@echo "Building performance test..."
	$(CC) $(CFLAGS) $(ALL_SOURCES) test/performance_test.c -o $@ $(LDFLAGS)

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

benchmark: $(BINDIR)/perf_test
	@echo "Running performance benchmark..."
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
	@echo "  make clean            - Remove all build artifacts"
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Runtime dispatch automatically selects the best implementation based on CPU features."

# Individual target shortcuts
perf_test: $(BINDIR)/perf_test
func_test: $(BINDIR)/func_test
test_vectors: $(BINDIR)/test_vectors
test_stream: $(BINDIR)/test_stream

# Phony targets
.PHONY: all test test-vectors benchmark clean help perf_test func_test test_vectors test_stream
