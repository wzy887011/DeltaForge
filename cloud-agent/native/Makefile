# 调用者: make — 交叉编译 forge (静态) + libforgehook.so + touch_injector
# 产物: forge, libforgehook.so, touch_injector (aarch64 ELF)
NDK ?= $(HOME)/Android/Sdk/ndk/26.3.11579264
TARGET = aarch64-linux-android21
CC = $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(TARGET)-clang
CFLAGS_STATIC = -static -Os -Wall -fno-stack-protector -fomit-frame-pointer
CFLAGS_SHARED = -shared -fPIC -Os -Wall -fno-stack-protector -DFORGEHOOK_VERSION=8

all: forge libforgehook.so touch_injector injector forge_monitor

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

injector: injector.c
	@if [ -f "$(CC)" ]; then \
		$(CC) -Os -Wall injector.c -o injector -ldl; \
		file injector; ls -lh injector; \
	else \
		gcc -Os -Wall injector.c -o injector -ldl; \
		file injector; ls -lh injector; \
	fi

forge_monitor: forge_monitor.c
	@if [ -f "$(CC)" ]; then \
		$(CC) $(CFLAGS_STATIC) forge_monitor.c -o forge_monitor; \
		file forge_monitor; ls -lh forge_monitor; \
	else \
		gcc -static -Os -Wall forge_monitor.c -o forge_monitor; \
		file forge_monitor; ls -lh forge_monitor; \
	fi

host:
	gcc -static -Os -Wall forge.c -o forge -lpthread
	gcc -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
	gcc -static -Os -Wall touch_injector.c -o touch_injector
	gcc -Os -Wall injector.c -o injector -ldl
	gcc -static -Os -Wall forge_monitor.c -o forge_monitor
	file forge libforgehook.so touch_injector injector forge_monitor
	ls -lh forge libforgehook.so touch_injector injector forge_monitor

# Termux 设备原生编译 — 无独立 libpthread/libc，去掉 -static/-lpthread
termux:
	clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge
	clang -shared -fPIC -Os -Wall -DFORGEHOOK_VERSION=8 libforgehook.c -o libforgehook.so -ldl
	clang -Os -Wall touch_injector.c -o touch_injector
	clang -Os -Wall injector.c -o injector -ldl
	clang -Os -Wall forge_monitor.c -o forge_monitor
	ls -lh forge libforgehook.so touch_injector injector forge_monitor

clean:
	rm -f forge libforgehook.so touch_injector injector forge_monitor
