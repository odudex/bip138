CC = gcc
CFLAGS = -Wall -Wextra -Werror=unused-result -std=c99 -g
LDFLAGS =
INCLUDES = -Iinclude -Isrc

# DEBUG=1 builds with ASan + UBSan; run `make clean` when toggling. WERROR=1
# turns warnings into errors, as CI does.
ifeq ($(DEBUG),1)
  CFLAGS += -O0 -fno-omit-frame-pointer -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
else
  CFLAGS += -O2
endif
ifeq ($(WERROR),1)
  CFLAGS += -Werror
endif

SOURCES = src/bip138_varint.c src/bip138_secret.c src/bip138_paths.c \
          src/bip138_payload.c src/bip138_container.c src/bip138_base64.c
OBJECTS = $(SOURCES:.c=.o)
LIB = src/libbip138.a

TEST_CRYPTO = test/test_crypto.o
TESTS = test/test_vectors test/test_api test/test_regressions
TEST_LIBS = -lmbedcrypto

all: $(LIB) $(TESTS)

$(LIB): $(OBJECTS)
	ar rcs $@ $^

src/%.o: src/%.c include/bip138.h src/bip138_internal.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TEST_CRYPTO): test/test_crypto.c test/test_crypto.h include/bip138.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

test/test_vectors: test/test_vectors.c test/vectors.h $(TEST_CRYPTO) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_CRYPTO) $(LIB) $(LDFLAGS) $(TEST_LIBS)

test/test_api: test/test_api.c test/vectors.h $(TEST_CRYPTO) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_CRYPTO) $(LIB) $(LDFLAGS) $(TEST_LIBS)

test/test_regressions: test/test_regressions.c $(TEST_CRYPTO) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_CRYPTO) $(LIB) $(LDFLAGS) $(TEST_LIBS)

run: $(TESTS)
	./test/test_vectors
	./test/test_api
	./test/test_regressions

vectors:
	python3 test/gen_vectors.py

# Compile-only portability check; requires GCC's 32-bit development headers.
check32:
	$(CC) $(CFLAGS) $(INCLUDES) -m32 -Werror=type-limits -fsyntax-only $(SOURCES) test/test_regressions.c

clean:
	rm -f $(OBJECTS) $(LIB) $(TEST_CRYPTO) $(TESTS)

.PHONY: all run vectors check32 clean
