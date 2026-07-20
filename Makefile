# 调用者: make — 交叉编译 forge (静态) + libforgehook.so + touch_injector
# 产物: forge, libforgehook.so, touch_injector (aarch64 ELF)
NDK ?= $(HOME)/Android/Sdk/ndk/26.3.11579264
TARGET = aarch64-linux-android21
CC = $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(TARGET)-clang
CFLAGS_STATIC = -static -Os -Wall -fno-stack-protector -fomit-frame-pointer
CFLAGS_SHARED = -shared -fPIC -Os -Wall -fno-stack-protector

all: forge libforgehook.so touch_injector

forge: forge.c
	@if [ -f "$(CC)" ]; then \
		$(CC) $(CFLAGS_STATIC) forge.c -o forge; \
		file forge; ls -lh forge; \
	else \
		echo "NDK not found at $(CC). Set NDK= or run: make host"; \
		exit 1; \
	fi

libforgehook.so: libforgehook.c
	@if [ -f "$(CC)" ]; then \
		$(CC) $(CFLAGS_SHARED) libforgehook.c -o libforgehook.so -ldl; \
		file libforgehook.so; ls -lh libforgehook.so; \
	else \
		echo "NDK not found. Set NDK= or run: make host"; \
		exit 1; \
	fi

touch_injector: touch_injector.c
	@if [ -f "$(CC)" ]; then \
		$(CC) $(CFLAGS_STATIC) touch_injector.c -o touch_injector; \
		file touch_injector; ls -lh touch_injector; \
	else \
		gcc -static -Os -Wall touch_injector.c -o touch_injector; \
		file touch_injector; ls -lh touch_injector; \
	fi

host:
	gcc -static -Os -Wall forge.c -o forge -lpthread
	gcc -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
	gcc -static -Os -Wall touch_injector.c -o touch_injector
	file forge; file libforgehook.so; file touch_injector
	ls -lh forge libforgehook.so touch_injector

clean:
	rm -f forge libforgehook.so touch_injector
