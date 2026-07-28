// ============================================================
// 法器: DeltaForge/cloud-agent/native/injector.c v8.5
// 描述: ptrace 注入器 — 自动解析 dlopen 所在库，正确计算目标地址
//   ARM64 W^X 严格 — 栈不可执行, 改用 ptrace+mmap 分配 RWX 内存
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
#include <dirent.h>
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

#include <fcntl.h>


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

/* ── 获取进程所有线程 TID ── */
static int get_all_tids(pid_t pid, pid_t *out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid > 0) out[n++] = tid;
    }
    closedir(d);
    return n;
}

/* kKillChain — patched while target is ptrace-paused, tersafe threads also paused */
static const struct { uint64_t off; uint32_t val; } kKillPatches[] = {
    {0x419fdcu, 0xD65F03C0u}, {0x419fe0u, 0xD65F03C0u},
    {0x2e7810u, 0xD65F03C0u}, {0x2f29d0u, 0xD65F03C0u},
    {0x320d78u, 0xD65F03C0u}, {0x3233b8u, 0xD65F03C0u},
};
static void patch_kill_chain_while_paused(pid_t pid) {
    uint64_t ts = find_lib_base(pid, "libtersafe.so");
    if (!ts) { printf("[*] libtersafe not in maps — skipping pre-patch\n"); return; }
    char mp[64]; snprintf(mp, sizeof(mp), "/proc/%d/mem", pid);
    int fd = open(mp, O_RDWR);
    if (fd < 0) { perror("[!] /proc/pid/mem"); return; }
    int ok = 0;
    for (int i = 0; i < 6; i++)
        if (pwrite(fd, &kKillPatches[i].val, 4, (off_t)(ts + kKillPatches[i].off)) == 4) ok++;
    close(fd);
    printf("[+] kKillChain pre-patch: %d/6 (ts=0x%llx, paused)\n", ok, (unsigned long long)ts);
}

/* ── 在目标进程中搜索 SVC #0 指令 ──
   遍历 libc.so / linker64 的 text 段, 找 0xD4000001。
   用于 ptrace 远程 syscall — 我们不能执行目标栈上的代码 (W^X)。 ── */
static uint64_t find_svc_gadget(pid_t pid) {
    const char *candidates[] = {"libc.so", "linker64", "libdl.so", NULL};
    char maps_path[64], mem_path[64], line[1024];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path,  sizeof(mem_path),  "/proc/%d/mem",  pid);
    FILE *mf = fopen(maps_path, "r");
    if (!mf) return 0;

    /* open /proc/pid/mem once, reuse across all candidate segments */
    int mem_fd = open(mem_path, O_RDONLY);

    uint64_t gadget = 0;
    /* fixed scan buffer — 64KB, reused across segments */
    static uint32_t scan_buf[16384];

    while (fgets(line, sizeof(line), mf) && !gadget) {
        uint64_t start, end; char perms[8], fname[256] = {0};
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
                   (unsigned long long *)&start,
                   (unsigned long long *)&end, perms, fname) < 3) continue;
        if (!(perms[0] == 'r' && perms[2] == 'x')) continue;

        const char *base = strrchr(fname, '/');
        base = base ? base + 1 : fname;
        int match = 0;
        for (int i = 0; candidates[i]; i++)
            if (strncmp(base, candidates[i], strlen(candidates[i])) == 0) { match = 1; break; }
        if (!match) continue;

        if (mem_fd < 0) continue;
        /* scan in 64KB chunks to cover segments larger than 2MB */
        uint64_t pos = start;
        while (pos < end && !gadget) {
            size_t chunk = sizeof(scan_buf);
            if (pos + chunk > end) chunk = (size_t)(end - pos);
            ssize_t n = pread(mem_fd, scan_buf, chunk, (off_t)pos);
            if (n <= 0) break;
            for (size_t i = 0; i < (size_t)n / 4; i++) {
                if (scan_buf[i] == 0xD4000001u) { gadget = pos + i * 4; break; }
            }
            pos += (uint64_t)n;
        }
    }
    if (mem_fd >= 0) close(mem_fd);
    fclose(mf);
    return gadget;
}

/* ── 在目标进程中执行一个 syscall ──
   用 PTRACE_SYSCALL: tracee 在 SVC #0 处进入/退出 syscall 时各停一次。
   返回: syscall 返回值 (x0), -1 表示 ptrace 失败。 ── */
static int64_t remote_syscall(pid_t pid, uint64_t svc_addr,
                              uint64_t sysno,
                              uint64_t a0, uint64_t a1, uint64_t a2,
                              uint64_t a3, uint64_t a4, uint64_t a5) {
    struct user_pt_regs regs, saved;
    if (ptrace_getregs(pid, &saved) != 0) return -1;

    memcpy(&regs, &saved, sizeof(regs));
    regs.regs[0]  = a0;
    regs.regs[1]  = a1;
    regs.regs[2]  = a2;
    regs.regs[3]  = a3;
    regs.regs[4]  = a4;
    regs.regs[5]  = a5;
    regs.regs[8]  = sysno;
    regs.pc       = svc_addr;
    /* point LR at a known BRK #0 so an accidental return traps cleanly */
    regs.regs[30] = svc_addr + 4;

    if (ptrace_setregs(pid, &regs) != 0) return -1;

    /* syscall-enter: tracee 跑到 SVC #0 并停下 */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        ptrace_setregs(pid, &saved); return -1;
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ptrace_setregs(pid, &saved); return -1;
    }
    if (!WIFSTOPPED(status)) {
        ptrace_setregs(pid, &saved); return -1;
    }

    /* syscall-exit: syscall 执行完, 停在 SVC 的下一条指令 */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        ptrace_setregs(pid, &saved); return -1;
    }
    if (waitpid(pid, &status, 0) == -1) {
        ptrace_setregs(pid, &saved); return -1;
    }
    if (!WIFSTOPPED(status)) {
        ptrace_setregs(pid, &saved); return -1;
    }

    struct user_pt_regs out;
    if (ptrace_getregs(pid, &out) != 0) {
        ptrace_setregs(pid, &saved); return -1;
    }

    int64_t result = (int64_t)out.regs[0];
    /* 恢复原始寄存器, 让进程可以继续正常运行 (PC 回到原位置) */
    ptrace_setregs(pid, &saved);
    return result;
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

    /* ── ATTACH main thread ── */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("ATTACH"); return 1;
    }
    int s; waitpid(pid, &s, 0);
    printf("[+] attached (main thread)\n");

    /* [v8.3] Attach ALL other threads to keep tersafe's integrity thread paused during dlopen.
     * PTRACE_ATTACH only stops one thread; other threads (including tersafe's integrity check)
     * keep running and will restore kKillChain + send SIGKILL during our dlopen → EINTR.
     * Fix: attach all threads, run dlopen with only main thread active. */
    pid_t tids[512]; int ntids = get_all_tids(pid, tids, 512);
    int nother = 0;
    for (int i = 0; i < ntids; i++) {
        if (tids[i] == pid) continue;
        if (ptrace(PTRACE_ATTACH, tids[i], NULL, NULL) == 0) {
            /* waitpid with timeout: poll up to 500ms per thread */
            int ws; int waited = 0;
            while (waited < 500) {
                pid_t r = waitpid(tids[i], &ws, WNOHANG | __WALL);
                if (r == tids[i]) { nother++; break; }
                if (r < 0) break;
                usleep(10000); waited += 10;
            }
            if (waited >= 500)
                ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
        }
    }
    printf("[+] frozen %d additional threads\n", nother);

    /* Patch kKillChain now that ALL threads are paused */
    patch_kill_chain_while_paused(pid);

    /* 保存寄存器 */
    struct user_pt_regs saved;
    if (ptrace_getregs(pid, &saved) != 0) {
        perror("getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* ── 解析 dlopen 地址 ──
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

    uint64_t offset = (uint64_t)local_dlopen - local_base;
    uint64_t fn_dlopen = target_base + offset;
    printf("[*] offset=0x%llx → 目标 dlopen=0x%llx\n",
           (unsigned long long)offset, (unsigned long long)fn_dlopen);

    /* ── v8.5: 分配 RWX 内存, 替代栈执行 ──
       ARM64 Android 严格 W^X, 栈无执行权限。旧方案把 shellcode 写到
       saved.sp - 0x300 再设 PC 过去 → SIGSEGV 在第一指令。
       修复: ptrace 远程调用 mmap 分配 PROT_READ|PROT_WRITE|PROT_EXEC
       内存, 把路径+shellcode 写入该区域再执行。 ── */

    /* 1. 找 SVC #0 gadget */
    uint64_t svc_addr = find_svc_gadget(pid);
    if (!svc_addr) {
        fprintf(stderr, "[-] 在目标进程中找不到 SVC #0 指令\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    printf("[*] SVC #0 gadget @ 0x%llx\n", (unsigned long long)svc_addr);

    /* 2. mmap RWX 内存 (2 页: 路径+代码+栈)
       先尝试 PROT_READ|PROT_WRITE|PROT_EXEC,
       若 SELinux 拒绝则退到 RW → 写 shellcode → mprotect RX */
    int64_t rwx_base = remote_syscall(pid, svc_addr,
                                      222,     /* __NR_mmap */
                                      0, 0x2000, 7, /* addr=NULL, size=8KB, prot=RWX */
                                      0x22,    /* MAP_PRIVATE|MAP_ANONYMOUS */
                                      (uint64_t)-1, 0  /* fd=-1, offset=0 */);
    int need_mprotect = 0;
    if (rwx_base < 0 || (uint64_t)rwx_base > 0xfffffffffffff000ULL) {
        /* 回退: mmap RW, 稍后 mprotect → RX */
        rwx_base = remote_syscall(pid, svc_addr,
                                  222, 0, 0x2000, 3,  /* prot=RW */
                                  0x22, (uint64_t)-1, 0);
        if (rwx_base < 0 || (uint64_t)rwx_base > 0xfffffffffffff000ULL) {
            fprintf(stderr, "[-] mmap 失败 — 无法分配内存\n");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        need_mprotect = 1;
        printf("[*] mmap RW @ 0x%llx (需 mprotect→RX)\n", (unsigned long long)rwx_base);
    } else {
        printf("[+] mmap RWX @ 0x%llx\n", (unsigned long long)rwx_base);
    }

    /* 3. 写路径和 shellcode */
    uint64_t rw_base = (uint64_t)rwx_base;
    uint64_t sc_addr  = rw_base + 0x400;   /* code at +1KB */
    uint64_t str_addr = rw_base;           /* path at start */
    /* 使用目标线程的真实栈，保留 TLS/thread-local 访问
     * 在原始 sp 下方 0x2000(8KB) 处落栈——不会踩现有帧，dlopen 内部调用链深度足够
     * 修复: 自定义孤立 4KB 栈导致 dlopen 在 Android12 内部调用链 SIGSEGV */
    uint64_t sp_addr  = (saved.sp - 0x2000) & ~0xFULL;

    printf("[*] str=0x%llx sc=0x%llx sp=0x%llx\n",
           (unsigned long long)str_addr,
           (unsigned long long)sc_addr,
           (unsigned long long)sp_addr);

    if (pv_writev(pid, str_addr, so, slen) != (ssize_t)slen) {
        fprintf(stderr, "[-] 写路径失败\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* ── 构造 shellcode ──
       movz/movk x16 = fn_dlopen
       movz/movk x0  = str_addr
       movz x1, #2   (RTLD_NOW)
       movz x2, #0
       blr x16
       brk #0
    ── */
    uint32_t code[24]; int n = 0;
    code[n++] = 0xD2800010 | ((fn_dlopen & 0xFFFF) << 5);
    if (((fn_dlopen >> 16) & 0xFFFF)) code[n++] = 0xF2A00010 | (((fn_dlopen >> 16) & 0xFFFF) << 5);
    if (((fn_dlopen >> 32) & 0xFFFF)) code[n++] = 0xF2C00010 | (((fn_dlopen >> 32) & 0xFFFF) << 5);
    if (((fn_dlopen >> 48) & 0xFFFF)) code[n++] = 0xF2E00010 | (((fn_dlopen >> 48) & 0xFFFF) << 5);
    code[n++] = 0xD2800000 | ((str_addr & 0xFFFF) << 5);
    if (((str_addr >> 16) & 0xFFFF)) code[n++] = 0xF2A00000 | (((str_addr >> 16) & 0xFFFF) << 5);
    if (((str_addr >> 32) & 0xFFFF)) code[n++] = 0xF2C00000 | (((str_addr >> 32) & 0xFFFF) << 5);
    if (((str_addr >> 48) & 0xFFFF)) code[n++] = 0xF2E00000 | (((str_addr >> 48) & 0xFFFF) << 5);
    code[n++] = 0xD2800041; code[n++] = 0xD2800002;
    code[n++] = 0xD63F0200; code[n++] = 0xD4200000;
    size_t clen = n * 4;

    if (pv_writev(pid, sc_addr, code, clen) != (ssize_t)clen) {
        fprintf(stderr, "[-] shellcode write failed\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    /* 4. 如果 mmap 只给了 RW, 现在 mprotect → RX */
    if (need_mprotect) {
        int64_t mpret = remote_syscall(pid, svc_addr,
                                       226,    /* __NR_mprotect */
                                       rw_base, 0x2000, 5  /* PROT_READ|PROT_EXEC */,
                                       0, 0, 0);
        if (mpret != 0) {
            fprintf(stderr, "[-] mprotect→RX 失败: 0x%llx (%s)\n",
                    (unsigned long long)mpret,
                    (uint64_t)mpret > 0xfffffffffffff000ULL ?
                    strerror((int)-(int64_t)mpret) : "OK");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 1;
        }
        printf("[+] mprotect→RX OK\n");
    }

    /* 5. 修改 PC 执行 shellcode */
    {
        struct user_pt_regs regs;
        memcpy(&regs, &saved, sizeof(regs));
        regs.pc = sc_addr;
        regs.sp = sp_addr;
        regs.regs[30] = 0;

        if (ptrace_setregs(pid, &regs) != 0) { perror("setregs"); return 1; }
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont"); return 1; }
    }

    /* ── 信号感知等待循环 (v8.4) ──
       dlopen 内部 syscall 可能被信号中断返回 EINTR。
       循环 waitpid, 检查 WSTOPSIG, 只在 SIGTRAP 时读取最终 handle,
       非 TRAP 信号 → 诊断 → EINTR 则重置 PC 重试。
       v8.5: PC=sc_addr(在 RWX 区), SP=sp_addr。 ── */
    uint64_t handle = 0;
    int done = 0;
    int retries = 0;
    const int max_retries = 10;
    int status;

    while (!done && retries <= max_retries) {
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            printf("[-] 目标进程退出 (exit=%d)\n", WEXITSTATUS(status));
            break;
        }

        if (WIFSIGNALED(status)) {
            int termsig = WTERMSIG(status);
            printf("[-] 目标进程被信号 %d (%s) 杀死%s\n",
                   termsig, strsignal(termsig),
                   WCOREDUMP(status) ? " (core dumped)" : "");
            break;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == SIGTRAP) {
                struct user_pt_regs out;
                if (ptrace_getregs(pid, &out) == 0) {
                    handle = out.regs[0];
                    printf("[*] dlopen returned x0=0x%llx (%s)\n",
                           (unsigned long long)handle,
                           (int64_t)handle < 0 ? strerror((int)-(int64_t)handle) : "OK");
                }
                done = 1;
            } else if (sig == SIGSEGV) {
                struct user_pt_regs out;
                ptrace_getregs(pid, &out);
                printf("[-] SIGSEGV at pc=0x%llx, x0=0x%llx — shellcode crash\n",
                       (unsigned long long)out.pc, (unsigned long long)out.regs[0]);
                break;
            } else {
                struct user_pt_regs out;
                ptrace_getregs(pid, &out);
                int64_t cur_x0 = (int64_t)out.regs[0];

                printf("[*] 信号 %d (%s) at pc=0x%llx, x0=0x%llx\n",
                       sig, strsignal(sig),
                       (unsigned long long)out.pc,
                       (unsigned long long)cur_x0);

                if (cur_x0 == -4) {
                    retries++;
                    printf("[*] EINTR 重试 %d/%d\n", retries, max_retries);
                    out.pc = sc_addr;
                    out.sp = sp_addr;
                    if (ptrace_setregs(pid, &out) != 0) {
                        perror("setregs(retry)"); break;
                    }
                    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
                        perror("cont(retry)"); break;
                    }
                } else if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                    printf("[*] 压制信号 %d, 继续执行\n", sig);
                    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
                        perror("cont(suppress)"); break;
                    }
                } else {
                    printf("[*] 转发信号 %d 到目标\n", sig);
                    if (ptrace(PTRACE_CONT, pid, NULL, (void*)(uintptr_t)sig) != 0) {
                        perror("cont(forward)"); break;
                    }
                }
            }
        }
    }

    if (!done) {
        fprintf(stderr, "[-] dlopen 未完成 (retries=%d, handle=0x%llx)\n",
                retries, (unsigned long long)handle);
    }

    /* 6. 恢复寄存器, detach 所有线程 */
    ptrace_setregs(pid, &saved);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    for (int i = 0; i < ntids; i++) {
        if (tids[i] == pid) continue;
        ptrace(PTRACE_DETACH, tids[i], NULL, (void*)0);
    }

    if (!handle || (int64_t)handle < 0) {
        fprintf(stderr, "[-] dlopen 失败 (handle=0x%llx, %s)\n",
                (unsigned long long)handle,
                handle ? strerror((int)-(int64_t)handle) : "NULL");
        return 1;
    }

    printf("[+] 注入完成 — libforgehook.so handle=0x%llx\n",
           (unsigned long long)handle);
    return 0;
}
