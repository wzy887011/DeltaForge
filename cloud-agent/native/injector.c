// ============================================================
// 法器: DeltaForge/cloud-agent/native/injector.c v5.8
// 描述: ptrace 注入器 — 自动解析 dlopen 所在库，正确计算目标地址
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

/* ── ARM64 pt_regs ──
   Termux NDK 的 <asm/ptrace.h> 已定义 user_pt_regs,
   用 __has_include 检测后优先使用系统定义 ── */
#if __has_include(<asm/ptrace.h>)
#include <asm/ptrace.h>
#else
struct user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
#endif

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

/* ── 在 maps 文件中找包含 addr 的 entry ──
   返回: entry 的 start (base); 出参 name_buf 填文件名 (basename only) ── */
static uint64_t find_containing_entry(const char *maps_path,
                                       uint64_t addr,
                                       char *name_out, size_t name_sz) {
    FILE *f = fopen(maps_path, "r");
    if (!f) { if (name_out) name_out[0] = '\0'; return 0; }

    char line[1024];
    uint64_t start, end;
    char perms[8];
    if (name_out) name_out[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llx-%llx %7s",
                   (unsigned long long *)&start,
                   (unsigned long long *)&end, perms) < 2) continue;
        if (addr < start || addr >= end) continue;

        if (name_out) {
            /* 路径在行末，以 '/' 开头 — 提取 basename */
            char *path = strchr(line, '/');
            if (path) {
                size_t plen = strlen(path);
                while (plen > 0 && (path[plen-1]=='\n'||path[plen-1]=='\r'||path[plen-1]==' '))
                    plen--;
                path[plen] = '\0';
                char *slash = strrchr(path, '/');
                const char *fname = slash ? slash + 1 : path;
                size_t flen = strlen(fname);
                if (flen > 0 && flen < name_sz)
                    memcpy(name_out, fname, flen + 1);
            } else {
                /* 匿名映射 [anon]/[stack] */
                char *b = strchr(line, '[');
                if (b) {
                    char *e2 = strchr(b, ']');
                    if (e2) {
                        size_t l = (size_t)(e2 - b + 1);
                        if (l < name_sz) { memcpy(name_out, b, l); name_out[l] = '\0'; }
                    }
                }
            }
        }
        fclose(f);
        return start;
    }

    fclose(f);
    if (name_out) name_out[0] = '\0';
    return 0;
}

/* ── 在 /proc/PID/maps 中找第一条匹配 library_name 的 r-xp entry ── */
static uint64_t find_lib_base(pid_t pid, const char *lib_name) {
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    uint64_t best = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, lib_name)) continue;
        /* 优先 r-xp (代码段，是真正的 base) */
        if (strstr(line, " r-xp ")) {
            fclose(f);
            return strtoull(line, NULL, 16);
        }
        /* 退而求其次: 有 x 权限的任意段 */
        if (!best && strchr(line, 'x'))
            best = strtoull(line, NULL, 16);
        /* 最后的退路: 第一段匹配 */
        if (!best)
            best = strtoull(line, NULL, 16);
    }
    fclose(f);
    return best;
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

    /* 检查目标是否已加载该 so（避免重复注入导致问题）
     * hijack 模式下 libforgehook.so 被重命名为 libtdmqimei.so 放到游戏目录,
     * 仅按参数 basename 搜会漏掉, 需同时搜 "forgehook" 和 hijack 副本 */
    {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *mf = fopen(maps_path, "r");
        if (mf) {
            char line[1024];
            const char *basename = strrchr(so, '/');
            basename = basename ? basename + 1 : so;
            int already = 0;
            while (fgets(line, sizeof(line), mf)) {
                if (strstr(line, basename)) { already = 1; break; }
                /* hijack 模式: libforgehook.so 以 libtdmqimei.so 名字加载,
                 * 但 /proc/pid/maps 中路径包含 "libtdmqimei" 且不是 _real 副本 */
                if (strstr(line, "libtdmqimei") && !strstr(line, "libtdmqimei_real")) { already = 1; break; }
                /* 兜底: 任何路径含 forgehook 即认为已加载 */
                if (strstr(line, "forgehook")) { already = 1; break; }
            }
            fclose(mf);
            if (already) {
                printf("[*] hook SO already loaded in target - skipping injection\n");
                return 0;
            }
        }
    }

    /* ── ATTACH ── */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("ATTACH"); return 1;
    }
    int s; waitpid(pid, &s, 0);
    printf("[+] attached\n");

    /* 保存寄存器 */
    struct user_pt_regs saved;
    if (ptrace_getregs(pid, &saved) != 0) {
        perror("getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* ── 路径字符串写到目标栈 ── */
    uint64_t str_addr = (saved.sp - 0x400) & ~0xFULL;
    printf("[*] 路径写入栈 0x%llx\n", (unsigned long long)str_addr);
    if (pv_writev(pid, str_addr, so, slen) != (ssize_t)slen) {
        fprintf(stderr, "[-] 写路径失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[+] 路径已写入\n");

    /* ── 正确解析 dlopen ──
       dlsym(RTLD_DEFAULT, "dlopen") 在 Android >= 7.0 上返回 libdl.so
       中地址。不能假设它在 linker64 里。用 /proc/self/maps 定位它
       落在哪个库 → 取该库文件名 → 在目标 /proc/PID/maps 找同名库 →
       offset 计算目标 dlopen 地址。 ── */
    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        fprintf(stderr, "[-] dlsym(dlopen) 本地失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[*] 本地 dlopen=0x%llx\n", (unsigned long long)local_dlopen);

    /* 1. 在 /proc/self/maps 定位 dlopen 所在 entry */
    char owner_full[256] = {0};
    uint64_t local_base = find_containing_entry("/proc/self/maps",
                                                  (uint64_t)local_dlopen,
                                                  owner_full, sizeof(owner_full));
    if (!local_base || !owner_full[0]) {
        fprintf(stderr, "[-] 无法在 /proc/self/maps 定位 dlopen 所在库\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[*] dlopen 在: %s (本地 base=0x%llx)\n",
           owner_full, (unsigned long long)local_base);

    /* 2. 取文件名部分，在目标 maps 中找同名库 */
    char *lib_name = strrchr(owner_full, '/');
    lib_name = lib_name ? lib_name + 1 : owner_full;
    printf("[*] 目标中搜索: %s\n", lib_name);

    uint64_t target_base = find_lib_base(pid, lib_name);
    if (!target_base) {
        fprintf(stderr, "[-] 在 /proc/%d/maps 找不到 %s\n", pid, lib_name);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[*] 目标 %s base=0x%llx\n", lib_name, (unsigned long long)target_base);

    /* 3. 正确计算 */
    uint64_t offset = (uint64_t)local_dlopen - local_base;
    uint64_t fn_dlopen = target_base + offset;
    printf("[*] offset=0x%llx → 目标 dlopen=0x%llx\n",
           (unsigned long long)offset, (unsigned long long)fn_dlopen);

    /* ── 构造 shellcode ──
       movz/movk x16 = fn_dlopen
       movz/movk x0  = str_addr
       movz x1, #2   (RTLD_NOW)
       movz x2, #0
       blr x16
       brk #0
    ── */
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
    code[n++] = 0xD2800041;
    code[n++] = 0xD2800002;

    /* blr x16; brk #0 */
    code[n++] = 0xD63F0200;
    code[n++] = 0xD4200000;

    /* ── 写 shellcode 到目标栈 ── */
    uint64_t sc_addr = (saved.sp - 0x300) & ~0xFULL;
    size_t clen = n * 4;
    if (pv_writev(pid, sc_addr, code, clen) != (ssize_t)clen) {
        fprintf(stderr, "[-] shellcode write failed\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* ── 修改 PC ── */
    struct user_pt_regs regs;
    memcpy(&regs, &saved, sizeof(regs));
    regs.pc = sc_addr;
    regs.sp = sc_addr - 0x80;
    regs.regs[30] = 0;

    if (ptrace_setregs(pid, &regs) != 0) { perror("setregs"); return 1; }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont"); return 1; }

    /* ── 等待 brk trap ── */
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

    /* ── 恢复寄存器并 detach ── */
    ptrace_setregs(pid, &saved);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    /* 检查 handle: NULL 或 error range (> 0xfffffffffffff000) 均失败 */
    if (!handle || (int64_t)handle < 0) {
        fprintf(stderr, "[-] dlopen 失败 (handle=0x%llx)\n",
                (unsigned long long)handle);
        return 1;
    }

    printf("[+] 注入完成 — libforgehook.so handle=0x%llx\n",
           (unsigned long long)handle);
    return 0;
}
