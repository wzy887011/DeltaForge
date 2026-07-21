// ============================================================
// 法器: DeltaForge/cloud-agent/native/injector.c
// 描述: ptrace 注入器 v2 — 直接 syscall 方式，不依赖 libc 函数
//   mmap: SVC #0 直接调 __NR_mmap (222)
//   dlopen: 用远程调用 libc dlopen（mmap 分配内存后写路径字符串）
// 原理: PTRACE_ATTACH → shellcode 调 mmap → pv_writev 写路径 →
//       shellcode 调 dlopen → DETACH
// 编译: clang -Os -Wall injector.c -o injector -ldl
// 用法: ./injector <PID> /data/local/tmp/libforgehook.so
// ============================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>

/* ===== ARM64 syscall numbers ===== */
#define ARM64_NR_MMAP      222
#define ARM64_NR_OPENAT    56
#define ARM64_NR_CLOSE     57
#define ARM64_NR_READ      63
#define ARM64_NR_WRITE     64

/* ===== 内存读写 ===== */
static ssize_t pv_writev(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    struct iovec local  = {(void *)buf, len};
    struct iovec remote = {(void *)(uintptr_t)addr, len};
    return syscall(271, pid, &local, 1, &remote, 1, 0);
}

/* ===== 寄存器操作 ===== */
static int ptrace_getregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = {regs, sizeof(*regs)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
}

static int ptrace_setregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = {(void *)regs, sizeof(*regs)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
}

/* ===== 模块基址查找 ===== */
static uint64_t find_base(pid_t pid, const char *module) {
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module)) { base = strtoull(line, NULL, 16); break; }
    }
    fclose(f);
    return base;
}

static uint64_t get_local_lib(const char *module) {
    char line[1024];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module)) { base = strtoull(line, NULL, 16); break; }
    }
    fclose(f);
    return base;
}

/*
 * 在目标进程中执行 shellcode（syscall 方式）
 * 1. 保存寄存器
 * 2. 往 SP-0x200 写 shellcode
 * 3. PC = shellcode_addr, SP = sc_addr - 0x80
 * 4. PTRACE_CONT
 * 5. wait SIGTRAP
 * 6. 读 x0 返回值
 * 7. 恢复寄存器
 */
static uint64_t exec_arm64_shellcode(pid_t pid, const uint32_t *code, size_t code_len) {
    struct user_pt_regs saved, regs;
    if (ptrace_getregs(pid, &saved) != 0) {
        perror("ptrace_getregs");
        return 0;
    }
    memcpy(&regs, &saved, sizeof(regs));

    uint64_t sc_addr = (regs.sp - 0x200) & ~0xFULL;
    if (pv_writev(pid, sc_addr, code, code_len) != (ssize_t)code_len) {
        fprintf(stderr, "[-] shellcode write failed\n");
        return 0;
    }

    regs.pc = sc_addr;
    regs.sp = sc_addr - 0x80;
    regs.regs[30] = 0; /* LR = 0 */
    if (ptrace_setregs(pid, &regs) != 0) { perror("ptrace_setregs"); return 0; }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("ptrace_cont"); return 0; }

    int status;
    if (waitpid(pid, &status, 0) == -1) { perror("waitpid"); return 0; }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] process not stopped: status=%x\n", status);
        ptrace_setregs(pid, &saved);
        return 0;
    }

    /* 读 x0 */
    struct user_pt_regs out_regs;
    ptrace_getregs(pid, &out_regs);
    uint64_t result = out_regs.regs[0];

    /* 恢复 */
    ptrace_setregs(pid, &saved);
    return result;
}

/*
 * 调用 syscall: x8=syscall_nr, x0-x5=args
 * 返回 x0
 */
static uint64_t remote_syscall(pid_t pid,
                                uint64_t nr,
                                uint64_t x0, uint64_t x1, uint64_t x2,
                                uint64_t x3, uint64_t x4, uint64_t x5) {
    /* 构造 x8=nr, x0-x5=args */
    uint64_t args[6] = {x0, x1, x2, x3, x4, x5};
    uint32_t code[32];
    int idx = 0;

    /* movz x8, nr */
    code[idx++] = 0xD2800008 | ((nr & 0xFFFF) << 5);
    if ((nr >> 16) & 0xFFFF) code[idx++] = 0xF2A00008 | (((nr >> 16) & 0xFFFF) << 5);

    /* movz/movk x0-x5 */
    for (int r = 0; r < 6; r++) {
        uint64_t v = args[r];
        if ((v >> 16) == 0 && (v >> 48) == 0) {
            /* 只有低 16 位或低于 16 位的值 */
            code[idx++] = 0xD2800000 | (r) | ((v & 0xFFFF) << 5);
        } else {
            code[idx++] = 0xD2800000 | (r) | ((v & 0xFFFF) << 5);
            if ((v >> 16) & 0xFFFF)
                code[idx++] = 0xF2A00000 | (r) | (((v >> 16) & 0xFFFF) << 5);
            if ((v >> 32) & 0xFFFF)
                code[idx++] = 0xF2C00000 | (r) | (((v >> 32) & 0xFFFF) << 5);
            if ((v >> 48) & 0xFFFF)
                code[idx++] = 0xF2E00000 | (r) | (((v >> 48) & 0xFFFF) << 5);
        }
    }

    /* svc #0 */
    code[idx++] = 0xD4000001;
    /* brk #0 */
    code[idx++] = 0xD4200000;

    return exec_arm64_shellcode(pid, code, idx * 4);
}

/*
 * 在目标进程中调用函数: x0-x2 = args, 跳转到 fn_addr, 返回 x0
 */
static uint64_t remote_call(pid_t pid, uint64_t fn_addr,
                             uint64_t x0_v, uint64_t x1_v, uint64_t x2_v) {
    uint32_t code[32];
    int idx = 0;

    /* movz/movk x16 = fn_addr */
    code[idx++] = 0xD2800010 | ((fn_addr & 0xFFFF) << 5);
    if (((fn_addr >> 16) & 0xFFFF))
        code[idx++] = 0xF2A00010 | (((fn_addr >> 16) & 0xFFFF) << 5);
    if (((fn_addr >> 32) & 0xFFFF))
        code[idx++] = 0xF2C00010 | (((fn_addr >> 32) & 0xFFFF) << 5);
    if (((fn_addr >> 48) & 0xFFFF))
        code[idx++] = 0xF2E00010 | (((fn_addr >> 48) & 0xFFFF) << 5);

    /* movz/movk x0,x1,x2 */
    uint64_t args[3] = {x0_v, x1_v, x2_v};
    for (int r = 0; r < 3; r++) {
        uint64_t v = args[r];
        code[idx++] = 0xD2800000 | (r) | ((v & 0xFFFF) << 5);
        if (((v >> 16) & 0xFFFF))
            code[idx++] = 0xF2A00000 | (r) | (((v >> 16) & 0xFFFF) << 5);
        if (((v >> 32) & 0xFFFF))
            code[idx++] = 0xF2C00000 | (r) | (((v >> 32) & 0xFFFF) << 5);
        if (((v >> 48) & 0xFFFF))
            code[idx++] = 0xF2E00000 | (r) | (((v >> 48) & 0xFFFF) << 5);
    }

    /* blr x16; brk #0 */
    code[idx++] = 0xD63F0200;
    code[idx++] = 0xD4200000;

    return exec_arm64_shellcode(pid, code, idx * 4);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <PID> <so_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    const char *so = argv[2];
    size_t slen = strlen(so) + 1;

    printf("[*] PID=%d SO=%s\n", pid, so);

    /* ATTACH */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("ATTACH");
        return 1;
    }
    int s;
    waitpid(pid, &s, 0);
    printf("[+] attached\n");

    /* mmap via direct syscall — 不需要知道目标 libc base */
    uint64_t str_addr = remote_syscall(pid, ARM64_NR_MMAP,
                                        0, slen, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS,
                                        0xFFFFFFFFFFFFFFFFULL, 0);

    printf("[*] mmap syscall returned: 0x%llx\n", (unsigned long long)str_addr);

    /*
     * 检查 mmap 返回值。在 ARM64 Linux 上，地址在 0x7????????? 范围是正常的，
     * 值 < 0x1000 是错误（errno），值 0xffffffffffffffXX 是负 errno
     */
    if (str_addr < 0x1000 || str_addr > 0x8000000000000000ULL) {
        fprintf(stderr, "[-] mmap 失败 (returned 0x%llx)\n", (unsigned long long)str_addr);
        fprintf(stderr, "    可能原因: seccomp 过滤/权限不足/内核限制\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* 写入路径字符串 */
    if (pv_writev(pid, str_addr, so, slen) != (ssize_t)slen) {
        fprintf(stderr, "[-] 写路径失败 (str_addr=0x%llx)\n", (unsigned long long)str_addr);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] 路径已写入 0x%llx\n", (unsigned long long)str_addr);

    /* 解析目标进程 dlopen 地址 */
    uint64_t local_linker = get_local_lib("linker64");
    uint64_t target_linker = find_base(pid, "linker64");
    if (!target_linker) target_linker = find_base(pid, "libdl.so");

    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen || !target_linker) {
        fprintf(stderr, "[-] dlopen 解析失败 local_dlopen=%p target_linker=0x%llx\n",
                local_dlopen, (unsigned long long)target_linker);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    uint64_t fn_dlopen = target_linker +
        ((uint64_t)local_dlopen - local_linker);

    printf("[*] dlopen=0x%llx\n", (unsigned long long)fn_dlopen);

    /* dlopen(so_path, RTLD_NOW) */
    uint64_t handle = remote_call(pid, fn_dlopen, str_addr, RTLD_NOW, 0);
    if (!handle) {
        fprintf(stderr, "[-] dlopen 返回 NULL\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] dlopen OK handle=0x%llx\n", (unsigned long long)handle);

    /* DETACH */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] 注入完成，已 detach\n");
    return 0;
}
