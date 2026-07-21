// ============================================================
// 法器: DeltaForge/cloud-agent/native/injector.c
// 描述: ptrace 注入器 v3 — 栈内存代替mmap, 直接远程调用dlopen
//   ARM64 上无 mmap syscall, 改用目标进程栈存放路径字符串
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

static ssize_t pv_writev(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    struct iovec local  = {(void *)buf, len};
    struct iovec remote = {(void *)(uintptr_t)addr, len};
    return syscall(271, pid, &local, 1, &remote, 1, 0);
}

static int ptrace_getregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = {regs, sizeof(*regs)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
}

static int ptrace_setregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = {(void *)regs, sizeof(*regs)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
}

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
        perror("ATTACH"); return 1;
    }
    int s; waitpid(pid, &s, 0);
    printf("[+] attached\n");

    /* 保存寄存器，用栈内存放路径字符串 */
    struct user_pt_regs saved;
    if (ptrace_getregs(pid, &saved) != 0) {
        perror("getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* 路径字符串写到目标进程栈上 (SP - 0x400), 不用 mmap */
    uint64_t str_addr = (saved.sp - 0x400) & ~0xFULL;
    printf("[*] 路径写入栈 0x%llx\n", (unsigned long long)str_addr);
    if (pv_writev(pid, str_addr, so, slen) != (ssize_t)slen) {
        fprintf(stderr, "[-] 写路径失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] 路径已写入\n");

    /* 解析目标 dlopen */
    uint64_t local_linker = get_local_lib("linker64");
    uint64_t target_linker = find_base(pid, "linker64");
    if (!target_linker) target_linker = find_base(pid, "libdl.so");

    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen || !target_linker || !local_linker) {
        fprintf(stderr, "[-] dlopen 解析失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    uint64_t fn_dlopen = target_linker +
        ((uint64_t)local_dlopen - local_linker);
    printf("[*] dlopen=0x%llx\n", (unsigned long long)fn_dlopen);

    /* 构造 shellcode:
     * movz/movk x16 = fn_dlopen
     * movz/movk x0 = str_addr
     * movz x1, #2  (RTLD_NOW)
     * movz x2, #0
     * blr x16
     * brk #0
     */
    uint32_t code[24];
    int n = 0;

    /* x16 = fn_dlopen */
    code[n++] = 0xD2800010 | ((fn_dlopen & 0xFFFF) << 5);
    if (((fn_dlopen >> 16) & 0xFFFF))
        code[n++] = 0xF2A00010 | (((fn_dlopen >> 16) & 0xFFFF) << 5);
    if (((fn_dlopen >> 32) & 0xFFFF))
        code[n++] = 0xF2C00010 | (((fn_dlopen >> 32) & 0xFFFF) << 5);
    if (((fn_dlopen >> 48) & 0xFFFF))
        code[n++] = 0xF2E00010 | (((fn_dlopen >> 48) & 0xFFFF) << 5);

    /* x0 = str_addr */
    code[n++] = 0xD2800000 | ((str_addr & 0xFFFF) << 5);
    if (((str_addr >> 16) & 0xFFFF))
        code[n++] = 0xF2A00000 | (((str_addr >> 16) & 0xFFFF) << 5);
    if (((str_addr >> 32) & 0xFFFF))
        code[n++] = 0xF2C00000 | (((str_addr >> 32) & 0xFFFF) << 5);
    if (((str_addr >> 48) & 0xFFFF))
        code[n++] = 0xF2E00000 | (((str_addr >> 48) & 0xFFFF) << 5);

    /* x1 = 2 (RTLD_NOW), x2 = 0 */
    code[n++] = 0xD2800041; /* movz x1, #2 */
    code[n++] = 0xD2800002; /* movz x2, #0 */

    /* blr x16; brk #0 */
    code[n++] = 0xD63F0200;
    code[n++] = 0xD4200000;

    /* 写入 shellcode 到目标栈 */
    uint64_t sc_addr = (saved.sp - 0x300) & ~0xFULL;
    size_t clen = n * 4;
    if (pv_writev(pid, sc_addr, code, clen) != (ssize_t)clen) {
        fprintf(stderr, "[-] shellcode write failed\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* 修改 PC 指向 shellcode */
    struct user_pt_regs regs;
    memcpy(&regs, &saved, sizeof(regs));
    regs.pc = sc_addr;
    regs.sp = sc_addr - 0x80;
    regs.regs[30] = 0;

    if (ptrace_setregs(pid, &regs) != 0) { perror("setregs"); return 1; }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont"); return 1; }

    int status;
    if (waitpid(pid, &status, 0) == -1) { perror("wait"); return 1; }

    uint64_t handle = 0;
    if (WIFSTOPPED(status)) {
        struct user_pt_regs out;
        ptrace_getregs(pid, &out);
        handle = out.regs[0];
        printf("[*] dlopen returned x0=0x%llx\n", (unsigned long long)handle);
    } else {
        printf("[-] unexpected status: 0x%x\n", status);
    }

    /* 恢复寄存器 */
    ptrace_setregs(pid, &saved);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if (!handle) {
        fprintf(stderr, "[-] dlopen 失败 (返回 NULL)\n");
        return 1;
    }

    printf("[+] 注入完成 — libforgehook.so handle=0x%llx\n", (unsigned long long)handle);
    return 0;
}
