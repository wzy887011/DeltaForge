// ============================================================
// 法器: DeltaForge/cloud-agent/native/injector.c
// 描述: ptrace 注入器 — 绕过 LD_PRELOAD 限制，远程注入 libforgehook.so
//       适用于 wrap 属性不生效的云手机/模拟器环境
// 原理: PTRACE_ATTACH → 保存寄存器 → shellcode 调 mmap →
//       写 so 路径字符串 → shellcode 调 dlopen → 恢复寄存器 → DETACH
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

/* 在目标进程中读写内存 */
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

/* 构建 shellcode: 设置 x0-x5, 调用目标函数, trap
 * 布局: LDR X16, .+shell_body_size → movz/movk x0-x5 → BLR X16 → BRK #0 → fn_addr
 * 共 12 条 mov 指令 (x0-x5 × 2 avg) + load + blr + brk + padding + fn_addr */
static size_t build_shellcode(uint32_t *code, size_t max,
                               uint64_t x0_v, uint64_t x1_v, uint64_t x2_v,
                               uint64_t x3_v, uint64_t x4_v, uint64_t x5_v,
                               uint64_t fn_addr) {
    int idx = 0;
    (void)max;

    /* slot 0: LDR X16, .+N — N 会在代码生成完后回填 */
    int ldr_slot = idx;
    code[idx++] = 0; /* placeholder */

    /* 每个参数: movz + upto 3 movk */
    uint64_t args[6] = {x0_v, x1_v, x2_v, x3_v, x4_v, x5_v};
    for (int r = 0; r < 6; r++) {
        uint64_t v = args[r];
        uint32_t movz = 0xD2800000 | (r << 0); /* movz Xr, #imm16 */
        code[idx++] = movz | ((v & 0xFFFF) << 5);
        if ((v >> 16) & 0xFFFF)
            code[idx++] = 0xF2A00000 | (r << 0) | (((v >> 16) & 0xFFFF) << 5);
        if ((v >> 32) & 0xFFFF)
            code[idx++] = 0xF2C00000 | (r << 0) | (((v >> 32) & 0xFFFF) << 5);
        if ((v >> 48) & 0xFFFF)
            code[idx++] = 0xF2E00000 | (r << 0) | (((v >> 48) & 0xFFFF) << 5);
    }

    /* BLR X16 */
    code[idx++] = 0xD63F0200;
    /* BRK #0 */
    code[idx++] = 0xD4200000;

    /* 对齐到 8 字节 */
    if (idx % 2) idx++;
    /* fn_addr */
    *(uint64_t *)&code[idx] = fn_addr;
    idx += 2;

    /* 回填 LDR X16, .+X — imm19 = (target_addr - pc) / 4
     * target = fn_addr 所在位置 (idx-2), pc = ldr 指令本身 (ldr_slot)
     * offset_bytes = (idx - 2 - ldr_slot) * 4, imm19 = offset_bytes / 4 */
    int imm19 = idx - 2 - ldr_slot;
    code[ldr_slot] = 0x58000010 | (((imm19 & 0x7FFFF) << 5));

    return idx * 4;
}

static int remote_call(pid_t pid, uint64_t fn_addr,
                       uint64_t x0_v, uint64_t x1_v, uint64_t x2_v,
                       uint64_t x3_v, uint64_t x4_v, uint64_t x5_v,
                       uint64_t *result) {
    struct user_pt_regs saved, regs;
    if (ptrace_getregs(pid, &saved) != 0) return -1;
    memcpy(&regs, &saved, sizeof(regs));

    uint64_t sc_addr = (regs.sp - 0x200) & ~0xFULL;
    uint32_t code[64]; /* 足够大 */
    size_t clen = build_shellcode(code, sizeof(code),
                                   x0_v, x1_v, x2_v, x3_v, x4_v, x5_v, fn_addr);

    if (pv_writev(pid, sc_addr, code, clen) != (ssize_t)clen) return -1;

    regs.pc = sc_addr;
    regs.sp = sc_addr - 0x80;
    regs.regs[30] = 0;
    if (ptrace_setregs(pid, &regs) != 0) return -1;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) return -1;

    int status;
    if (waitpid(pid, &status, 0) == -1) return -1;
    if (!WIFSTOPPED(status)) { ptrace_setregs(pid, &saved); return -1; }

    if (result) { ptrace_getregs(pid, &regs); *result = regs.regs[0]; }
    ptrace_setregs(pid, &saved);
    return 0;
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

    /* 解析目标函数地址 */
    uint64_t local_linker = get_local_lib("linker64");
    uint64_t target_linker = find_base(pid, "linker64");
    if (!target_linker) target_linker = find_base(pid, "libdl.so");

    uint64_t local_libc = get_local_lib("libc.so");
    uint64_t target_libc = find_base(pid, "libc.so");

    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    void *local_mmap   = dlsym(RTLD_DEFAULT, "mmap");

    if (!local_dlopen || !local_mmap || !target_libc) {
        fprintf(stderr, "[-] 函数解析失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    uint64_t fn_dlopen = target_linker ?
        target_linker + ((uint64_t)local_dlopen - local_linker) :
        target_libc  + ((uint64_t)local_dlopen - local_libc);
    uint64_t fn_mmap   = target_libc + ((uint64_t)local_mmap - local_libc);

    printf("[*] dlopen=0x%llx mmap=0x%llx\n",
           (unsigned long long)fn_dlopen, (unsigned long long)fn_mmap);

    /* mmap(0, slen, RW, PRIVATE|ANON, -1, 0) — 6 args */
    uint64_t str_addr = 0;
    if (remote_call(pid, fn_mmap, 0, slen, 3, 0x22, 0xFFFFFFFFFFFFFFFFULL, 0, &str_addr) != 0 || !str_addr || str_addr < 0x1000) {
        fprintf(stderr, "[-] mmap 失败, returned 0x%llx\n", (unsigned long long)str_addr);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] mmap: 0x%llx\n", (unsigned long long)str_addr);

    /* 写路径字符串 */
    if (pv_writev(pid, str_addr, so, slen) != (ssize_t)slen) {
        fprintf(stderr, "[-] 写路径失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] 路径已写入\n");

    /* dlopen(so, RTLD_NOW=2) */
    uint64_t handle = 0;
    if (remote_call(pid, fn_dlopen, str_addr, 2, 0, 0, 0, 0, &handle) != 0 || !handle) {
        fprintf(stderr, "[-] dlopen 失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] dlopen OK handle=0x%llx\n", (unsigned long long)handle);

    /* DETACH */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] 注入完成\n");
    return 0;
}
