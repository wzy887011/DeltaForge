// ============================================================
// libforgehook.c v8.0 — LD_PRELOAD 注入库
// Android syscall 拦截 + 属性模拟 + GPU 适配 + 文件伪造
// 编译: clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl -lpthread
// v7.1 新增: CRYPT_STR 加密宏 (P0) / 标识符随机化 (P1) / JUNK_INSN (P2)
//           mremap 匿名重映射 (P3) / 属性流量混淆 (P4)
// v8.0 新增: FIX-A ACQUIRE原子读 / FIX-B constructor(50)动态扩容
//           FIX-C maps无上限缓冲 / NEW-1 statx+faccessat2 hook
//           NEW-2 getdents64 memfd过滤 / NEW-3 smaps_rollup+numa_maps
//           NEW-4 pattern_scan_seq多指令扫描 / NEW-5 chainload后删磁盘so
// ============================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/uio.h>
#include <jni.h>
#include <time.h>
#include <link.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* [v7.1 P0] 字符串常量加密 — 防 strings/IDA 检索 */
#include "crypt_strings.h"

/* [v7.1 P2] 垃圾指令注入宏
 * 防: 静态特征码匹配 — 插入无语义 ARM64 指令改变函数字节模式。
 * AND x0,x0,x0 = 0x8A000000 (保留 x0 不变，消耗一个时钟)
 * ORR x1,x1,xzr = 0xAA1F0021 (orr x1,x1,xzr — 保留 x1 不变)
 * 每次调用会生成不同 ASM 序列，在不同优化级别下编译结果也略有差异。*/
#define JUNK_INSN() __asm__ __volatile__( \
    "and x0, x0, x0\n\t" \
    "orr x1, x1, xzr\n\t" \
    ::: "memory")

#define JUNK_INSN2() __asm__ __volatile__( \
    "orr x2, x2, xzr\n\t" \
    "and x3, x3, x3\n\t" \
    ::: "memory")

/* forward declarations — 函数定义在后，但前向构造函数中需要引用 */
static uintptr_t get_module_base(const char *so_name);
static void hook_log(const char *msg);
static int patch_insn(uintptr_t addr, uint32_t insn);

/* seccomp-bpf constants */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1U<<0)
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW      0x7fff0000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP       0x00030000U
#endif
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7
#endif

/* ARM64 syscall numbers */
#define ARM64_NR_OPENAT      56
#define ARM64_NR_EXIT_GROUP   94  /* exit_group — terminate all threads */
#define ARM64_NR_KILL        129  /* kill — process-wide signal */
#define ARM64_NR_TKILL       130  /* tkill — per-thread signal */
#define ARM64_NR_TGKILL      131  /* tgkill — target module direct SVC termination */
#define ARM64_NR_GETDENTS64  216
#define ARM64_NR_PROCESS_VM_READV 270
#define ARM64_NR_PROCESS_VM_WRITEV 271
#define ARM64_NR_OPENAT2     437
#define ARM64_NR_FACCESSAT2  439

struct sock_filter { uint16_t code; uint8_t jt,jf; uint32_t k; };
struct sock_fprog   { uint16_t len; struct sock_filter *filter; };

#define BPF_LD   0x00
#define BPF_LDX  0x01
#define BPF_ALU  0x04
#define BPF_JMP  0x05
#define BPF_RET  0x06
#define BPF_MISC 0x07
#define BPF_W    0x00
#define BPF_ABS  0x20
#define BPF_JEQ  0x10
#define BPF_JGE  0x30
#define BPF_JGT  0x20
#define BPF_JSET 0x40
#define BPF_JA   0x00
#define BPF_K    0x00
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif

/* ============================================================
 * [v7.1 P1] 每次启动随机化标识符
 * 防: 多次运行的二进制被 memfd 名/日志文件名指纹识别。
 * 方案: constructor(48) 生成 6 位 hex 随机后缀，所有 memfd/shm 名
 * 均附加后缀; /data/local/tmp 固定路径保持不变 (deploy.sh 依赖)。
 * ============================================================ */
static char g_rand_sfx[8] = {0};   /* "XXXXXX\0" — 6 hex chars */

static void _gen_rand_suffix(void) {
    /* 来源: /dev/urandom 优先，失败则 getpid()^time()^stack_addr 异或 */
    uint32_t seed = 0;
    int ufd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (ufd >= 0) {
        (void)syscall(SYS_read, ufd, &seed, 4);
        syscall(SYS_close, ufd);
    }
    if (!seed) {
        seed = (uint32_t)((uintptr_t)g_rand_sfx ^ (uint32_t)getpid()
                         ^ (uint32_t)time(NULL));
    }
    /* snprintf 不可用（libc 可能未初始化），手写 hex 编码 */
    static const char hex[] = "0123456789abcdef";
    g_rand_sfx[0] = hex[(seed >> 28) & 0xF];
    g_rand_sfx[1] = hex[(seed >> 24) & 0xF];
    g_rand_sfx[2] = hex[(seed >> 20) & 0xF];
    g_rand_sfx[3] = hex[(seed >> 16) & 0xF];
    g_rand_sfx[4] = hex[(seed >> 12) & 0xF];
    g_rand_sfx[5] = hex[(seed >>  8) & 0xF];
    g_rand_sfx[6] = '\0';
}

/* 辅助: 将后缀拼到 base 后，写入 out_buf */
static void make_sfx_name(const char *base, char *out_buf, size_t out_sz) {
    size_t bl = 0; while (base[bl]) bl++;
    size_t sl = 6; /* g_rand_sfx 长度固定 6 */
    if (bl + sl + 1 > out_sz) { /* 截断保护 */
        size_t room = (out_sz > 1) ? out_sz - 1 : 0;
        for (size_t i = 0; i < room && i < bl; i++) out_buf[i] = base[i];
        out_buf[room] = '\0';
        return;
    }
    for (size_t i = 0; i < bl; i++) out_buf[i] = base[i];
    for (size_t i = 0; i < sl; i++) out_buf[bl + i] = g_rand_sfx[i];
    out_buf[bl + sl] = '\0';
}

/* [v7.1 Fix 2] constructor(48) — 双路径日志 + P1 随机后缀生成
 * v7.0 问题: 仅写 /data/local/tmp/forge_hook.log (权限 0600)。
 * 修复: 双路径 (主+fallback)，权限 0666; 同时初始化随机后缀。 */
__attribute__((constructor(48)))
static void _probe_loaded(void) {
    /* P1: 首先生成随机后缀（其他所有构造函数依赖此值）*/
    _gen_rand_suffix();

    const char *log_paths[] = {
        C_forgehook_log,            /* 主: /data/local/tmp/ */
        "/sdcard/forge_hook.log"   /* fallback: sdcard 权限宽松 */
    };
    const char *msg = "[CTOR] 48 probe v7.1 enter\n";
    size_t mlen = 0; while (msg[mlen]) mlen++;

    for (int lp = 0; lp < 2; lp++) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, log_paths[lp],
            O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd >= 0) {
            (void)syscall(SYS_write, fd, msg, mlen);
            syscall(SYS_close, fd);
        }
    }
    msg = "[CTOR] 48 probe v7.1 done\n";
    mlen = 0; while (msg[mlen]) mlen++;
    for (int lp = 0; lp < 2; lp++) {
        int fd = (int)syscall(SYS_openat, AT_FDCWD, log_paths[lp],
            O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd >= 0) {
            (void)syscall(SYS_write, fd, msg, mlen);
            syscall(SYS_close, fd);
        }
    }
}

/* [v7.1 P3] constructor(50) — mremap 匿名重映射
 * 防: /proc/self/maps 扫描 — madvise(DONTDUMP) 不改变 maps 路径条目，
 *     任何读 maps 的检测仍能看到 "libforgehook" 字样(在我们的过滤器之外的地方)。
 * 方案: 对每个包含 libforgehook 的 RW/RX 段:
 *   1. mmap 一块等大的匿名内存
 *   2. memcpy 原内容 → 匿名页
 *   3. mremap(MREMAP_FIXED|MREMAP_MAYMOVE) 将匿名页移到原地址
 *   → maps 中该条目变为 "[anon]"，再加上 make_filtered_maps_fd() 作双重防护
 * 注: 仅在 inject 模式下安全(游戏已初始化)；对 .text 段只做 MADV_DONTDUMP
 *     不做 mremap(重映射可执行段可能触发 SIGBUS)。 */
__attribute__((constructor(50)))
static void _hide_self_from_maps(void) {
    hook_log("[CTOR] 50 _hide_self_from_maps enter\n");
    srand(time(NULL)^getpid()^(long)pthread_self());

    int rfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (rfd < 0) { hook_log("[CTOR] 50 maps open FAILED\n"); return; }

    /* [v8 FIX-B] 动态扩容替代 64KB 栈缓冲 — 大型游戏进程 maps 可超 64KB */
    size_t cap = 131072; /* 128KB 起步 */
    char *buf = NULL;
    ssize_t nr = 0;
    while (cap <= 4 * 1024 * 1024) {
        if (buf) munmap(buf, cap / 2 + 1);
        buf = (char *)mmap(NULL, cap + 1, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) { buf = NULL; break; }
        if (lseek(rfd, 0, SEEK_SET) != 0) break;
        nr = 0; ssize_t n;
        while ((n = (ssize_t)syscall(SYS_read, rfd, buf + nr,
                                     cap - (size_t)nr)) > 0) nr += n;
        if ((size_t)nr < cap) break;
        cap *= 2;
    }
    syscall(SYS_close, rfd);
    if (!buf || nr <= 0) { if (buf && buf != MAP_FAILED) munmap(buf, cap+1); return; }
    buf[nr] = '\0';

    char *line = buf;
    while (line && *line) {
        char *eol = __builtin_strchr(line, '\n');
        if (!eol) break; *eol = '\0';

        if (strstr(line, C_forgehook) || strstr(line, C_qimei_underscore)) {
            uintptr_t start = (uintptr_t)strtoul(line, NULL, 16);
            char *dash = __builtin_strchr(line, '-');
            uintptr_t end = dash ? (uintptr_t)strtoul(dash+1, NULL, 16) : start;
            size_t len = end - start;
            char *perm = dash ? __builtin_strchr(dash, ' ') : NULL;
            int is_exec = perm && perm[1]=='r' && perm[3]=='x'; /* r-xp */

            if (len > 0 && len < 32*1024*1024) {
                if (is_exec) {
                    /* 可执行段: 只做 MADV_DONTDUMP，不 mremap */
                    madvise((void*)start, len, MADV_DONTDUMP);
                } else {
                    /* 数据段: mremap → 匿名页，maps 条目变为 [anon] */
                    void *anon = mmap(NULL, len, PROT_READ|PROT_WRITE,
                                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                    if (anon != MAP_FAILED) {
                        memcpy(anon, (void*)start, len);
                        /* mprotect 原段为 RW 以允许 mremap 覆盖 */
                        mprotect((void*)start, len, PROT_READ|PROT_WRITE);
                        void *res = mremap(anon, len, len,
                                           MREMAP_FIXED|MREMAP_MAYMOVE,
                                           (void*)start);
                        if (res == MAP_FAILED) {
                            /* mremap 失败 fallback DONTDUMP */
                            munmap(anon, len);
                            madvise((void*)start, len, MADV_DONTDUMP);
                            hook_log("[P3] mremap FAILED, fallback DONTDUMP\n");
                        } else {
                            hook_log("[P3] mremap anon ok\n");
                        }
                    }
                }
            }
        }
        *eol = '\n'; line = eol + 1;
    }
    munmap(buf, cap + 1); /* [v8 FIX-B] 释放动态缓冲 */
    hook_log("[CTOR] 50 _hide_self_from_maps done\n");
}

/* ---- audit log — buffered writes for I/O efficiency ---- */
#define AUDIT_BUF_SIZE 32768
static char  g_audit_buf[AUDIT_BUF_SIZE];
static int   g_audit_pos = 0;

static void flush_audit(void) {
    if (g_audit_pos <= 0) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD,
        "/data/data/com.tencent.tmgp.dfm/files/forge_audit.log",
        O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) { g_audit_pos = 0; return; }
    (void)syscall(SYS_write, fd, g_audit_buf, (size_t)g_audit_pos);
    syscall(SYS_close, fd);
    g_audit_pos = 0;
}

static void forge_audit(const char *action, const char *path) {
    if (!path || path[0] == '\0') return;
    if (!strstr(path, "/data/data/com.tencent") &&
        !strstr(path, "/proc/") &&
        !strstr(path, "/sys/") &&
        !strstr(path, "/sdcard/Tencent"))
        return;
    int n = snprintf(g_audit_buf + g_audit_pos,
        (size_t)(AUDIT_BUF_SIZE - g_audit_pos),
        "[GAP][%s] %s\n", action, path);
    if (n > 0) {
        g_audit_pos += n;
        if (g_audit_pos >= AUDIT_BUF_SIZE - 640) flush_audit();
    }
}


/* ---- chainload original native library ---- */
/* 保存 chainloaded 原版 qimei 的 dlopen handle，供 JNI_OnLoad 转发 */
static void *g_real_qimei_handle = NULL;

static void forge_log_raw(const char *msg) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, C_forge_log,
                          O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) return;
    size_t len = 0;
    while (msg[len]) len++;
    while (len) {
        ssize_t n = (ssize_t)syscall(SYS_write, fd, msg, len);
        if (n <= 0) break;
        msg += n;
        len -= (size_t)n;
    }
    syscall(SYS_close, fd);
}

static int dirname_join_real(const char *self_path, char *out, size_t out_sz) {
    const char *slash = strrchr(self_path, '/');
    if (!slash) return 0;
    size_t dir_len = (size_t)(slash - self_path + 1);
    const char *real_name = C_forgehook_real;
    size_t real_len = 0;
    while (real_name[real_len]) real_len++;
    if (dir_len + real_len + 1 > out_sz) return 0;
    for (size_t i = 0; i < dir_len; i++) out[i] = self_path[i];
    for (size_t i = 0; i <= real_len; i++) out[dir_len + i] = real_name[i];
    return 1;
}

static int find_self_from_maps(char *out, size_t out_sz) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, C_maps_path, O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[32768];
    ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* 逐行解析，找包含 libtdmqimei 的行，提取路径列 (第6列，'/'开头) */
    const char *needle = C_qimei;
    char *line = buf;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        if (strstr(line, needle)) {
            char *path = strchr(line, '/');
            if (path) {
                size_t len = strlen(path);
                while (len > 0 && (path[len-1]==' '||path[len-1]=='\t'||path[len-1]=='\r'))
                    len--;
                if (len > 0 && len < out_sz) {
                    memcpy(out, path, len);
                    out[len] = '\0';
                    if (eol) *eol = '\n';
                    return 1;
                }
            }
        }

        if (!eol) break;
        *eol = '\n';
        line = eol + 1;
    }
    return 0;
}

/* CRITICAL: constructor(47) — MUST be earliest constructor.
 * Android linker ALWAYS uses BIND_NOW (RTLD_NOW), resolving all symbols
 * during link_image() Phase 2 BEFORE constructors run in Phase 3.
 * Any library that DT_NEEDED-depends on libtdmqimei.so will have its
 * symbols resolved from OUR so (since we replaced the original).
 * RTLD_GLOBAL chainload of libtdmqimei_real.so in constructor(47)
 * ensures qimei symbols are available for all subsequent loads. */
/* [v7.0 P1-1] constructor(47) 只解析路径，不调 dlopen
 * 修复: 原版在 constructor 内直接 dlopen，Android 10+ linker 的
 * g_dl_mutex 不可重入，constructor 持锁期间再 dlopen → 死锁。
 * dlopen 推迟到后台线程 (_do_chainload)，通过 pthread_once 单次执行。*/
static char g_real_qimei_path[1024] = {0};
static pthread_once_t g_chainload_once = PTHREAD_ONCE_INIT;

static void _do_chainload(void) {
    if (!g_real_qimei_path[0]) { forge_log_raw("chainload: no path\n"); return; }
    dlerror();
    void *h = dlopen(g_real_qimei_path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        const char *err = dlerror();
        hook_log("[chainload] FAILED: "); hook_log(err ? err : "(null)"); hook_log("\n");
        return;
    }
    g_real_qimei_handle = h;
    forge_log_raw("chainload: dlopen SUCCESS\n");
    hook_log("[chainload] done\n");
    /* [v8 NEW-5] dlopen 后立即删除磁盘文件 — so 已映射到内存，删 inode 不影响运行
     * 防: tersafe 通过 /data/app/ 路径扫描发现 libtdmqimei_real.so 磁盘文件 */
    if (g_real_qimei_path[0]) {
        syscall(SYS_unlinkat, AT_FDCWD, g_real_qimei_path, 0);
        hook_log("[chainload] disk so unlinked\n");
    }
}

__attribute__((constructor(47)))
static void _resolve_qimei_path(void) {
    hook_log("[CTOR] 47 enter\n");
    char self_path[1024] = {0};
    Dl_info info;
    if (dladdr((void *)&_resolve_qimei_path, &info) && info.dli_fname &&
        dirname_join_real(info.dli_fname, g_real_qimei_path, sizeof(g_real_qimei_path))) {
        forge_log_raw("chainload: path via dladdr\n");
    } else if (find_self_from_maps(self_path, sizeof(self_path)) &&
               dirname_join_real(self_path, g_real_qimei_path, sizeof(g_real_qimei_path))) {
        forge_log_raw("chainload: path via maps\n");
    } else {
        forge_log_raw("chainload: path unresolved\n");
    }
    hook_log("[CTOR] 47 done\n");
}

/* ---- override data tables ---- */
/* Snapdragon 8+ Gen1 (SM8475): 1xX2(0xd48)+3xA710(0xd47)+4xA510(0xd46) */
static const char OVERRIDE_CPUINFO[]=
"processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd46\nCPU revision\t: 0\n\n"
"processor\t: 1\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd46\nCPU revision\t: 0\n\n"
"processor\t: 2\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd46\nCPU revision\t: 0\n\n"
"processor\t: 3\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x2\nCPU part\t: 0xd46\nCPU revision\t: 0\n\n"
"processor\t: 4\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd47\nCPU revision\t: 0\n\n"
"processor\t: 5\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd47\nCPU revision\t: 0\n\n"
"processor\t: 6\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd47\nCPU revision\t: 0\n\n"
"processor\t: 7\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xd48\nCPU revision\t: 0\n\n"
"Hardware\t: Qualcomm Technologies, Inc Kailua\n";

static const char OVERRIDE_STAT[]=
"cpu  1567890 45678 890123 45678901 23456 0 12345 0 0 0\n"
"cpu0 195678 5678 110123 5701234 3456 0 2345 0 0 0\n"
"cpu1 196789 5789 111234 5698901 2890 0 1890 0 0 0\n"
"cpu2 194567 4890 109876 5712345 3100 0 1678 0 0 0\n"
"cpu3 197890 5234 112345 5687890 2900 0 1456 0 0 0\n"
"cpu4 195432 6012 108765 5723456 3100 0 1234 0 0 0\n"
"cpu5 196789 5567 111234 5690123 2678 0 1567 0 0 0\n"
"cpu6 194321 5890 109876 5712345 2890 0 1345 0 0 0\n"
"cpu7 198424 4618 112670 5679012 3442 0 830 0 0 0\n"
"intr 9876543210 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
"ctxt 12345678901\nbtime 1700000000\nprocesses 456789\nprocs_running 3\nprocs_blocked 0\n";

static const char OVERRIDE_VERSION[]=
"Linux version 5.15.74-android13-8-25801347 (Android (9915937, based on r49823797) "
"clang version 17.0.2 (https://android.googlesource.com/toolchain/llvm-project "
"d8a40ab03cb5e4c0bba11ef115e93c2574e55a1b), "
"LLD 17.0.2) #1 SMP PREEMPT Wed Feb 14 08:22:10 UTC 2024\n";

static const char OVERRIDE_CMDLINE[]=
"androidboot.hardware=qcom androidboot.bootloader=unknown "
"androidboot.veritymode=enforcing androidboot.verifiedbootstate=green "
"androidboot.slot_suffix=_a buildvariant=user rootwait ro init=/init "
"rcupdate.rcu_expedited=1 rcu_nocbs=0-7\n";

static const char OVERRIDE_MODULES[]="\n";
static const char OVERRIDE_DEVICES[]=
"Character devices:\n  1 mem\n  4 tty\n  5 /dev/tty\n  5 /dev/console\n"
" 10 misc\n 13 input\n 29 fb\n 81 video4linux\n 89 i2c\n 90 mtd\n"
"108 ppp\n128 ptm\n136 pts\n180 usb\n189 usb_device\n"
"202 cpu/msm_cpu\n239 apex\n240 ttyDBC\n241 ttyMSM\n242 media\n"
"243 hidraw\n244 gpu\n245 kgsl-3d0\n246 ion\n247 smd\n248 bsg\n"
"249 ptp\n250 pps\n251 rtc\n252 dsp\n253 ttyGS\n254 rpmsg\n\n"
"Block devices:\n  8 sd\n 65 sd\n179 mmc\n253 device-mapper\n254 mdp\n259 blkext\n";

static const char OVERRIDE_BATTERY[]="5000000\n";
static const char OVERRIDE_BAT_STAT[]="Discharging\n";
static const char OVERRIDE_BAT_TEMP[]="320\n";
static const char OVERRIDE_BAT_VOLT[]="4200000\n";
static const char OVERRIDE_THERMAL[]="38000\n";
static const char OVERRIDE_CPU_PRES[]="0-7\n";
static const char OVERRIDE_CPU_ONLINE[]="0-7\n";
static const char OVERRIDE_CPU_GOV[]="schedutil\n";
static const char OVERRIDE_GPU_NAME[]="Adreno (TM) 740\n";
static const char OVERRIDE_GPU_GOV[]="msm-adreno-tz\n";
static const char OVERRIDE_GPU_MAX[]="680000000\n";
static const char OVERRIDE_HARDWARE[]="Qualcomm Technologies, Inc Kailua\n";
static const char OVERRIDE_MACHINE[]="Snapdragon 8+ Gen1\n";

/* [v7.0 P2-1] /proc/self/status — 动态 PID，消除硬编码 12345 被识别风险 */
#define PROC_STATUS_FMT \
"Name:\tGameActivity\nUmask:\t0077\nState:\tS (sleeping)\n" \
"Tgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t1199\nTracerPid:\t0\n" \
"Uid:\t10600\t10600\t10600\t10600\nGid:\t10600\t10600\t10600\t10600\n" \
"FDSize:\t256\nGroups:\t3003 9997 20000\nNStgid:\t%d\nNSpid:\t%d\n" \
"NSpgid:\t%d\nNSsid:\t%d\nVmPeak:\t10485760 kB\nVmSize:\t9437184 kB\n" \
"VmLck:\t0 kB\nVmPin:\t0 kB\nVmHWM:\t524288 kB\nVmRSS:\t458752 kB\n" \
"Threads:\t48\n"

static char g_proc_status_buf[512];
static int  g_proc_status_len = 0;

static void ensure_proc_status(void) {
    if (g_proc_status_len > 0) return;
    pid_t tgid = getpid();
    pid_t tid  = (pid_t)syscall(SYS_gettid);
    g_proc_status_len = snprintf(g_proc_status_buf, sizeof(g_proc_status_buf),
        PROC_STATUS_FMT, tgid, tid, tgid, tid, tgid, tgid);
    if (g_proc_status_len < 0 || g_proc_status_len >= (int)sizeof(g_proc_status_buf))
        g_proc_status_len = 0;
}

/* /proc/self/environ — 清空，隐藏 LD_PRELOAD 等注入痕迹 */
static const char OVERRIDE_ENVIRON[]="PATH=/system/bin:/system/xbin\0ANDROID_DATA=/data\0\0";

/* [v8 NEW-3] /proc/self/numa_maps — 返回空，防 NUMA 拓扑探测 */
static const char OVERRIDE_NUMA_MAPS[]="";
/* [v8 NEW-3] /proc/self/smaps_rollup — 极简 rollup 防内存布局分析 */
static const char OVERRIDE_SMAPS_ROLLUP[]=
"00400000-7fc0000000 ---p 00000000 00:00 0\n"
"Rss:           458752 kB\nPss:           224768 kB\n"
"Shared_Clean:       0 kB\nShared_Dirty:       0 kB\n"
"Private_Clean:  65536 kB\nPrivate_Dirty: 393216 kB\n"
"Referenced:    458752 kB\nAnonymous:     393216 kB\n"
"AnonHugePages:      0 kB\nShmemPmdMapped:     0 kB\n"
"Shared_Hugetlb:     0 kB\nPrivate_Hugetlb:    0 kB\n"
"Swap:               0 kB\nSwapPss:            0 kB\nLocked:             0 kB\n";

/* /proc/net/tcp — 空响应，不暴露调试端口 */
static const char OVERRIDE_NET_TCP[]=
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";

/* /proc/net/tcp6 — 空 IPv6 连接表 */
static const char OVERRIDE_NET_TCP6[]=
"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";

/* /proc/net/udp + /proc/net/udp6 — 空连接表 */
static const char OVERRIDE_NET_UDP[]=
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
static const char OVERRIDE_NET_UDP6[]=
"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";

static const char OVERRIDE_INPUT_DEVS[]=
"I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
"N: Name=\"gpio-keys\"\nP: Phys=gpio-keys/input0\n"
"S: Sysfs=/devices/platform/soc/soc:gpio_keys/input/input1\n"
"H: Handlers=kbd event1 keychord\nB: PROP=0\nB: EV=3\nB: KEY=10000 0 0 0\n\n"
"I: Bus=0000 Vendor=0000 Product=0000 Version=0000\n"
"N: Name=\"fts_ts\"\nP: Phys=\n"
"S: Sysfs=/devices/platform/soc/ae00000.i2c/i2c-0/0-0049/input/input2\n"
"H: Handlers=event2\nB: PROP=2\nB: EV=b\nB: KEY=400 0 0 0 0 0 0 0 0 0 0 0\n"
"B: ABS=6618000 0\n";

/* ---- null redirect list — redirect analytics/telemetry files only ---- */
static const char *NULL_REDIRECT[]={
    "crashSight_db_",      /* CrashSight crash database */
    "ace_shell_db.dat",    /* ACE shell database */
    "ace_cache_db.dat",    /* ACE 缓存数据库 */
    "tersafe.update",      /* Security module update package */
    "tdm_track.dat",       /* TDM tracking data */
    "sys_log_",            /* CrashSight system log */
    "jni_log_",            /* CrashSight JNI log */
    /* 注意: tgpa.xml / tdm.xml / GCloudCoreSP.xml / GPMSDK.mmap3 /
     *       mmkvlite_log_app_state.mmkv 不在此处 — 游戏 SDK 读写这些文件，
     *       重定向到空 memfd 会导致 SDK 崩溃。改由 forge.c 定期清理。 */
    NULL
};

static int null_redir(const char *p){
    if(!p) return 0;
    for(const char **n=NULL_REDIRECT;*n;n++)
        if(strstr(p,*n)) return 1;
    return 0;
}

/* [v7.1 P1] memfd_anon — 随机化 memfd 名称防指纹识别 */
static int memfd_anon(void){
    char nm[16] = "ac_";
    nm[3] = g_rand_sfx[0]; nm[4] = g_rand_sfx[1]; nm[5] = '\0';
    int fd=(int)syscall(__NR_memfd_create, nm, 0);
    if(fd<0){
        char sh[32] = "/dev/shm/.ac_";
        sh[13]=g_rand_sfx[0];sh[14]=g_rand_sfx[1];sh[15]=g_rand_sfx[2];sh[16]='\0';
        fd=syscall(SYS_openat,AT_FDCWD,sh,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    }
    return fd;
}

/* ---- file routing table ---- */
typedef struct {const char *pat;const char *data;size_t len;}override_file_t;
static const override_file_t OVERRIDE_FILES[]={
    {"/proc/cpuinfo",OVERRIDE_CPUINFO,sizeof(OVERRIDE_CPUINFO)-1},
    {"/proc/stat",OVERRIDE_STAT,sizeof(OVERRIDE_STAT)-1},
    {"/proc/bus/input/devices",OVERRIDE_INPUT_DEVS,sizeof(OVERRIDE_INPUT_DEVS)-1},
    {"/proc/version",OVERRIDE_VERSION,sizeof(OVERRIDE_VERSION)-1},
    {"/proc/cmdline",OVERRIDE_CMDLINE,sizeof(OVERRIDE_CMDLINE)-1},
    {"/proc/modules",OVERRIDE_MODULES,1},
    {"/proc/devices",OVERRIDE_DEVICES,sizeof(OVERRIDE_DEVICES)-1},
    {"/sys/devices/system/cpu/present",OVERRIDE_CPU_PRES,4},
    {"/sys/devices/system/cpu/possible",OVERRIDE_CPU_PRES,4},
    {"/sys/devices/system/cpu/kernel_max","7\n",2},
    {"/sys/devices/system/cpu/offline","\n",1},
    {"/sys/devices/system/cpu/online",OVERRIDE_CPU_ONLINE,4},
    {"/sys/devices/system/cpu/cpu",OVERRIDE_CPU_GOV,10},
    {"/sys/class/power_supply/battery/capacity",OVERRIDE_BATTERY,9},
    {"/sys/class/power_supply/battery/status",OVERRIDE_BAT_STAT,sizeof(OVERRIDE_BAT_STAT)-1},
    {"/sys/class/power_supply/battery/temp",OVERRIDE_BAT_TEMP,5},
    {"/sys/class/power_supply/battery/voltage_now",OVERRIDE_BAT_VOLT,9},
    {"/sys/class/thermal/thermal_zone",OVERRIDE_THERMAL,6},
    {"/sys/class/kgsl/kgsl-3d0/gpu_model",OVERRIDE_GPU_NAME,sizeof(OVERRIDE_GPU_NAME)-1},
    {"/sys/class/kgsl/kgsl-3d0/devfreq/governor",OVERRIDE_GPU_GOV,sizeof(OVERRIDE_GPU_GOV)-1},
    {"/sys/class/kgsl/kgsl-3d0/max_gpuclk",OVERRIDE_GPU_MAX,sizeof(OVERRIDE_GPU_MAX)-1},
    {"/sys/class/kgsl/kgsl-3d0/gpuclk",OVERRIDE_GPU_MAX,sizeof(OVERRIDE_GPU_MAX)-1},
    {"/sys/devices/soc0/hardware",OVERRIDE_HARDWARE,sizeof(OVERRIDE_HARDWARE)-1},
    {"/sys/devices/soc0/soc_id","500\n",4},
    {"/sys/devices/soc0/machine",OVERRIDE_MACHINE,sizeof(OVERRIDE_MACHINE)-1},
    {"/sys/devices/soc0/family","Snapdragon\n",11},
    {"/sys/class/sensors/","\n",1},
    /* /proc/PID/status and /proc/self/status handled by open hook dynamically
     * (includes real PID). These are placeholder entries for the match table. */
    {"/proc/net/tcp",OVERRIDE_NET_TCP,sizeof(OVERRIDE_NET_TCP)-1},
    {"/proc/net/tcp6",OVERRIDE_NET_TCP6,sizeof(OVERRIDE_NET_TCP6)-1},
    {"/proc/net/udp",OVERRIDE_NET_UDP,sizeof(OVERRIDE_NET_UDP)-1},
    {"/proc/net/udp6",OVERRIDE_NET_UDP6,sizeof(OVERRIDE_NET_UDP6)-1},
    {"/proc/self/environ",OVERRIDE_ENVIRON,sizeof(OVERRIDE_ENVIRON)-1},
    /* /status 由 open hook 动态处理，确保 Tgid/Pid 为真实值 */
    /* [v7.0 New] 补全遗漏的 /proc 检测路径 */
    {"/proc/self/wchan",   "do_epoll_wait\n", 14},
    {"/wchan",             "do_epoll_wait\n", 14},
    {"/proc/self/syscall", "7 0x0 0x0 0x0 0x0 0x0 0x0 0x7fff00000000\n", 42},
    {"/syscall",           "7 0x0 0x0 0x0 0x0 0x0 0x0 0x7fff00000000\n", 42},
    {"/proc/self/attr/current","u:r:untrusted_app:s0:c180,c256,c512,c768\n",41},
    {"/attr/current",         "u:r:untrusted_app:s0:c180,c256,c512,c768\n",41},
    {"/fdinfo/",           "pos:\t0\nflags:\t0102002\nmnt_id:\t25\nino:\t0\n", 40},
    /* [v8 NEW-3] smaps_rollup + numa_maps 显式覆盖 */
    {"/smaps_rollup",     OVERRIDE_SMAPS_ROLLUP, sizeof(OVERRIDE_SMAPS_ROLLUP)-1},
    {"/numa_maps",        OVERRIDE_NUMA_MAPS,    1},
    {NULL,NULL,0}
};

static const char *HIDDEN[]={
    "/sys/class/misc/qemu","/sys/class/misc/vbox",
    "/sys/class/misc/vhost","/sys/bus/virtio",
    "/sys/bus/virtio/devices","/sys/bus/virtio/drivers",
    "/sys/devices/virtual","/sys/firmware/qemu",
    "/sys/hypervisor",
    "/dev/tee0","/dev/tee1","/dev/teepriv0",  /* virtual TEE device */
    "/dev/qemu_pipe","/dev/socket/qemud","/dev/goldfish_pipe",
    "/system/bin/qemud","/system/bin/qemu-props",
    "/system/bin/androVM-prop","/system/bin/microvirt-prop",
    "/system/bin/nox-prop","/system/bin/ttVM-prop",
    "/system/bin/droid4x-prop","/system/bin/nemud-prop",
    "/system/bin/genymotion-prop","/system/bin/windroye-prop",
    "/system/lib/libdroid4x.so",
    "/system/lib/vbox","/system/lib/ko",
    "/proc/iomem","/proc/ioports",
    "/proc/device-tree","/proc/sys/abi",
    "/proc/kallsyms","/proc/tty/drivers",
    "/data/local/tmp/frida-server","/data/local/tmp/frida-server-",
    "/data/local/tmp/gdbserver","/data/local/tmp/re.frida.server",
    "/data/local/tmp/re.frida.gadget","/data/local/tmp/frida",
    "/system/bin/magisk","/system/bin/supersu",
    "/sbin/su","/system/xbin/su",
    "/system/bin/failsafe/su","/system/app/Superuser",
    "/system/app/SuperSU","/sbin/magisk",
    "/sbin/.magisk","/system/framework/XposedBridge.jar",
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.lsposed.manager",
    "/data/local/tmp/x8","/data/local/tmp/sandbox",
    "/data/local/tmp/inject",
    NULL
};

/* [v7.1 P1] override_fd — 随机化 memfd/shm 名防指纹 */
static int override_fd(const char *s, size_t n) {
    char nm[16] = "fh_";
    nm[3]=g_rand_sfx[0]; nm[4]=g_rand_sfx[1]; nm[5]='\0';
    int fd = syscall(__NR_memfd_create, nm, 0);
    if (fd < 0) {
        char sh[32] = "/dev/shm/.fh_";
        sh[13]=g_rand_sfx[0];sh[14]=g_rand_sfx[1];sh[15]=g_rand_sfx[2];sh[16]='\0';
        fd = syscall(SYS_openat, AT_FDCWD, sh, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        if (ftruncate(fd,(off_t)n) != 0) { close(fd); return -1; }
    } else {
        if (ftruncate(fd,(off_t)n) != 0) { close(fd); return -1; }
    }
    void *a=mmap(NULL,n,PROT_WRITE,MAP_SHARED,fd,0);
    if(a==MAP_FAILED){close(fd);return -1;}  /* P1: 不再 unlink 固定路径 */
    memcpy(a,s,n);munmap(a,n);lseek(fd,0,SEEK_SET);
    return fd;
}

static const override_file_t *match(const char *p){
    if(!p)return NULL;
    for(const override_file_t *f=OVERRIDE_FILES;f->pat;f++)
        if(strstr(p,f->pat))return f;
    return NULL;
}

static int hidden(const char *p){
    if(!p)return 0;
    for(const char **h=HIDDEN;*h;h++)
        if(*h&&strstr(p,*h))return 1;
    return 0;
}

static int is_virtio_path(const char *p){
    if(!p)return 0;
    if(strstr(p,"/sys/bus/virtio/devices/"))return 1;
    if(strstr(p,"/sys/devices/virtual/"))return 1;
    if(strstr(p,"/sys/bus/virtio"))return 1;
    return 0;
}

static int safe_read_path(uint64_t addr,char *buf,size_t max){
    if(addr==0||addr>0x7fffffffffffULL)return -1;
    struct iovec local={buf,max};
    struct iovec remote={(void*)(uintptr_t)addr,max};
    memset(buf,0,max);
    ssize_t n=syscall(270,getpid(),&local,1,&remote,1,0);
    if(n<=0)return -1;
    if((size_t)n<max)buf[n]='\0';else buf[max-1]='\0';
    return 0;
}

/* ---- libc function hooks ---- */
typedef int (*open_t)(const char*,int,...);
typedef int (*openat_t)(int,const char*,int,...);
typedef FILE* (*fopen_t)(const char*,const char*);
typedef int (*acc_t)(const char*,int);
typedef int (*stat_t)(const char*,struct stat*);
typedef ssize_t (*readlink_t)(const char*,char*,size_t);
typedef ssize_t (*readlinkat_t)(int,const char*,char*,size_t);

static open_t _open=NULL;
static openat_t _openat=NULL;
static fopen_t _fopen=NULL;
static acc_t _access=NULL;
static stat_t _stat=NULL;
static stat_t _lstat=NULL;
static readlink_t _readlink=NULL;
static readlinkat_t _readlinkat=NULL;

/* [v7.0 P0-2] /proc/self/maps 动态过滤
 * 修复: 原 char buf[65536] 静态缓冲，大型游戏进程 maps 超 64KB 时被截断，
 * 导致注入痕迹残留在超出部分。新版本动态扩容，最多读取 2MB。
 * [v7.0 P3-1] 扩展过滤名单：新增 libgadget/libzygisk/libsubstrate */
static int make_filtered_maps_fd(void) {
    int rfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (rfd < 0) return -1;

    /* [v8 FIX-C] 动态扩容无上限 — 移除 2MB 硬限，大型游戏 maps 可达数 MB */
    size_t cap = 262144;
    char *raw = NULL;
    ssize_t total = 0;
    while (1) {
        if (lseek(rfd, 0, SEEK_SET) != 0) break;
        raw = (char *)mmap(NULL, cap + 1, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (raw == MAP_FAILED) { raw = NULL; break; }
        total = 0;
        ssize_t n;
        while ((n = (ssize_t)syscall(SYS_read, rfd, raw+total,
                                     cap-(size_t)total)) > 0)
            total += n;
        if ((size_t)total < cap) break; /* 没读满，说明已全部读取 */
        munmap(raw, cap + 1); raw = NULL; cap *= 2; /* 翻倍继续 */
    }
    syscall(SYS_close, rfd);
    if (!raw || total <= 0) { if (raw) munmap(raw, cap+1); return -1; }
    raw[total] = '\0';

    static const char *FILTER_SONAMES[] = {
        "libforgehook", "libtdmqimei_real", "libqimei_",
        "libinject",    "libfrida",         "libsubstrate",
        "libxposed",    "libgadget",        "libzygisk",
        NULL
    };

    int mfd = (int)syscall(__NR_memfd_create, "mp_" , 0);
    if (mfd < 0) { munmap(raw, cap+1); return -1; }

    char *line = raw, *out = raw;
    size_t out_len = 0;
    while (line && *line) {
        char *eol = strchr(line, '\n'); if (!eol) break;
        *eol = '\0';
        int keep = 1;
        for (const char **s = FILTER_SONAMES; *s; s++)
            if (strstr(line, *s)) { keep = 0; break; }
        if (keep) {
            size_t ll = (size_t)(eol - line) + 1;
            memmove(out + out_len, line, ll);
            out_len += ll;
        }
        *eol = '\n'; line = eol + 1;
    }
    if (out_len > 0) {
        if (ftruncate(mfd, (off_t)out_len) != 0) {
            syscall(SYS_close, mfd); munmap(raw, cap+1); return -1; }
        void *a = mmap(NULL, out_len, PROT_WRITE, MAP_SHARED, mfd, 0);
        if (a == MAP_FAILED) {
            syscall(SYS_close, mfd); munmap(raw, cap+1); return -1; }
        memcpy(a, out, out_len); munmap(a, out_len);
        lseek(mfd, 0, SEEK_SET);
    }
    munmap(raw, cap+1);
    return mfd;
}

/* ============================================================
 * CRITICAL: g_hooks_ready — 延迟激活所有 libc hook
 *
 * BUG (v6.0, 数小时排查): hijack 模式 (替换 libtdmqimei.so) 下游戏闪退，
 * ptrace 注入模式 (forge -l) 正常工作。根因是加载时机差异:
 *   hijack: so 在进程第一瞬间加载 → open/fopen/tgkill/connect/getaddrinfo
 *           /__system_property_get 等 hook 在 ART/动态链接器/UE4 引擎
 *           初始化之前就拦截了所有系统调用 → 进程静默死亡
 *   inject: so 在游戏完全初始化后 ptrace 注入 → hook 不影响初始化
 *
 * FIX: g_hooks_ready 初始为 0，constructor(150) 完成后设为 1。
 *      所有 hook 在 g_hooks_ready=0 期间透传原始调用，不做任何拦截。
 *      这样 hijack 和 inject 两种模式都安全——hijack 的 hook 在游戏
 *      初始化完成后才生效。
 *
 * 血的教训: 永远不要在 LD_PRELOAD/hijack 场景下让 hook 进程启动阶段
 * 就介入。加延迟激活是最小代价的解决方案。
 * ============================================================ */
static volatile int g_hooks_ready = 0;

/* [v8 FIX-A] ACQUIRE 原子读 — ARM64 弱内存序下确保 patch 线程的
 * g_hooks_ready=1 (RELEASE) 写入对所有 hook 线程可见。
 * volatile 不提供内存屏障，仅保证编译器不优化掉该次读取。 */
#define HOOKS_READY() __atomic_load_n(&g_hooks_ready, __ATOMIC_ACQUIRE)

#define INIT() do{ \
    if(!_open)_open=(open_t)dlsym(RTLD_NEXT,"open"); \
    if(!_openat)_openat=(openat_t)dlsym(RTLD_NEXT,"openat"); \
    if(!_fopen)_fopen=(fopen_t)dlsym(RTLD_NEXT,"fopen"); \
    if(!_access)_access=(acc_t)dlsym(RTLD_NEXT,"access"); \
    if(!_stat)_stat=(stat_t)dlsym(RTLD_NEXT,"stat"); \
    if(!_lstat)_lstat=(stat_t)dlsym(RTLD_NEXT,"lstat"); \
    if(!_readlink)_readlink=(readlink_t)dlsym(RTLD_NEXT,"readlink"); \
    if(!_readlinkat)_readlinkat=(readlinkat_t)dlsym(RTLD_NEXT,"readlinkat"); \
}while(0)

int open(const char *p,int flags,...){
    JUNK_INSN();   /* [P2] 破坏静态特征码 */
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(!HOOKS_READY()) return _open(p,flags,m);
    if(hidden(p)){errno=ENOENT;return -1;}
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    /* [v7.0 P0-2] smaps 动态过滤 (同 maps 逻辑) */
    if(p && strstr(p,"smaps") && strstr(p,"/proc/")){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    /* maps 动态过滤 */
    if(p && strstr(p,"maps") && (strstr(p,"/proc/self/")||(strstr(p,"/proc/") && strstr(p,"/task/")))){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    /* [v7.0 P2-1] /proc/PID/status dynamically generated (includes real PID) */
    if(p && strstr(p,"/status") && strstr(p,"/proc/") && !(flags&O_WRONLY)){
        ensure_proc_status();
        if(g_proc_status_len>0){int fd=override_fd(g_proc_status_buf,(size_t)g_proc_status_len);if(fd>=0)return fd;}
    }
    const override_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=override_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("open",p);
    return _open(p,flags,m);
}

int openat(int dir,const char *p,int flags,...){
    JUNK_INSN2();   /* [P2] */
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(!HOOKS_READY()) return _openat(dir,p,flags,m);
    if(hidden(p)){errno=ENOENT;return -1;}
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    if(p && strstr(p,"smaps") && strstr(p,"/proc/")){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    if(p && strstr(p,"maps") && (strstr(p,"/proc/self/")||(strstr(p,"/proc/") && strstr(p,"/task/")))){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    if(p && strstr(p,"/status") && strstr(p,"/proc/") && !(flags&O_WRONLY)){
        ensure_proc_status();
        if(g_proc_status_len>0){int fd=override_fd(g_proc_status_buf,(size_t)g_proc_status_len);if(fd>=0)return fd;}
    }
    const override_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=override_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("openat",p);
    return _openat(dir,p,flags,m);
}

FILE *fopen(const char *p,const char *m){
    INIT();
    if(!HOOKS_READY()) return _fopen(p,m);
    if(hidden(p)){errno=ENOENT;return NULL;}
    if(null_redir(p)){
        /* 写入模式 → /dev/null；读取模式 → 空内存 */
        if(m[0]=='w'||m[0]=='a') return _fopen("/dev/null",m);
        static char nb[64]={0}; FILE *fp=fmemopen(nb,sizeof(nb),"r"); if(fp) return fp;
    }
    const override_file_t *f=match(p);
    if(f&&m[0]=='r'){FILE *fp=fmemopen((void*)f->data,f->len,m);if(fp)return fp;}
    if(!f&&!hidden(p)) forge_audit("fopen",p);
    return _fopen(p,m);
}

int access(const char *p,int m){INIT();if(!HOOKS_READY()) return _access(p,m);if(hidden(p)){errno=ENOENT;return -1;}forge_audit("access",p);return _access(p,m);}
int stat(const char *p,struct stat *b){INIT();if(!HOOKS_READY()) return _stat(p,b);if(hidden(p)){errno=ENOENT;return -1;}forge_audit("stat",p);return _stat(p,b);}
int lstat(const char *p,struct stat *b){INIT();if(!HOOKS_READY()) return _lstat(p,b);if(hidden(p)){errno=ENOENT;return -1;}return _lstat(p,b);}
ssize_t readlink(const char *p,char *buf,size_t sz){INIT();if(!HOOKS_READY()) return _readlink(p,buf,sz);if(hidden(p)){errno=ENOENT;return -1;}return _readlink(p,buf,sz);}
ssize_t readlinkat(int dir,const char *p,char *buf,size_t sz){INIT();if(!HOOKS_READY()) return _readlinkat(dir,p,buf,sz);if(hidden(p)){errno=ENOENT;return -1;}return _readlinkat(dir,p,buf,sz);}

/* [v8 NEW-1] statx syscall hook
 * Android 5.10+ 内核优先使用 statx(291) 替代 stat/lstat。
 * 不 hook 会导致 tersafe 通过 statx 探测到我们隐藏的路径。*/
#ifndef SYS_statx
#define SYS_statx 291
#endif
long statx(int dirfd, const char *path, int flags,
           unsigned int mask, void *statxbuf) {
    if (!HOOKS_READY())
        return syscall(SYS_statx, dirfd, path, flags, mask, statxbuf);
    if (path && hidden(path)) { errno = ENOENT; return -1; }
    return syscall(SYS_statx, dirfd, path, flags, mask, statxbuf);
}

/* [v8 NEW-1] faccessat2 syscall hook
 * glibc 2.33+ / Android 12+ 的 access() 内部改用 faccessat2(439)。
 * 直接 SVC 调用 faccessat2 可绕过 libc access() 的 PLT hook。*/
long faccessat2(int dirfd, const char *path, int mode, int flags) {
    if (!HOOKS_READY())
        return syscall(ARM64_NR_FACCESSAT2, dirfd, path, mode, flags);
    if (path && hidden(path)) { errno = ENOENT; return -1; }
    return syscall(ARM64_NR_FACCESSAT2, dirfd, path, mode, flags);
}

/* [v8 NEW-2] getdents64 syscall hook
 * 过滤 /proc/<pid>/fd 目录中的 "memfd:" 和 "forgehook" 条目。
 * 防: tersafe 枚举 /proc/self/fd 发现注入库和匿名内存文件描述符。*/
typedef struct {
    uint64_t d_ino; int64_t d_off; uint16_t d_reclen;
    uint8_t d_type; char d_name[1];
} lde64_t;

long getdents64(int fd, void *dirp, size_t count) {
    long nread = syscall(ARM64_NR_GETDENTS64, fd, dirp, count);
    if (!HOOKS_READY() || nread <= 0) return nread;
    long pos = 0, out_len = 0;
    while (pos < nread) {
        lde64_t *d = (lde64_t *)((char *)dirp + pos);
        pos += d->d_reclen;
        const char *n = d->d_name;
        if (strstr(n, "memfd:") || strstr(n, "forgehook") ||
            strstr(n, "fh_") || strstr(n, "ac_") || strstr(n, "mp_"))
            continue;
        /* 如果出现空洞则压缩，否则原地跳过 */
        if (out_len != (long)((char *)d - (char *)dirp))
            memmove((char *)dirp + out_len, d, (size_t)d->d_reclen);
        out_len += d->d_reclen;
    }
    return out_len;
}

/* tersafe 代码段范围 — 用于 tgkill/exit_group 调用方检测 */
static uintptr_t   g_ts_text_start = 0;
static uintptr_t   g_ts_text_end   = 0;

typedef int (*tgkill_t)(pid_t, pid_t, int);
typedef int (*kill_t)(pid_t, int);
static tgkill_t _tgkill = NULL;
static kill_t   _kill_fn = NULL;

/* [v7.0 Patch A] tgkill — 拦截来自 libtersafe 代码段的所有终止信号
 * 原版只拦截 sig==9/15，tersafe 可能发 SIGABRT(6) 等信号自杀绕过拦截。
 * 修复: 检查 return address 是否在 libtersafe 代码段内；
 *       来自 tersafe 的任何 sig(除 0/SIGCHLD/SIGPIPE) 都被丢弃。*/
int tgkill(pid_t tgid, pid_t tid, int sig) {
    if (!_tgkill) _tgkill = (tgkill_t)dlsym(RTLD_NEXT, "tgkill");
    if (!HOOKS_READY()) return _tgkill ? _tgkill(tgid, tid, sig) : 0;
    /* 检查调用方是否在 libtersafe 代码段 */
    if (g_ts_text_start) {
        JUNK_INSN2();   /* [P2] */
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (ra >= g_ts_text_start && ra < g_ts_text_end) {
            if (sig != 0 && sig != SIGCHLD && sig != SIGPIPE && sig != SIGUSR1)
                return 0;  /* 来自 tersafe 的终止信号，静默丢弃 */
        }
    }
    if (sig == 9 || sig == 15) return 0;  /* 兜底：任何来源的 SIGKILL/SIGTERM */
    return _tgkill ? _tgkill(tgid, tid, sig) : 0;
}

int kill(pid_t pid, int sig) {
    if (!_kill_fn) _kill_fn = (kill_t)dlsym(RTLD_NEXT, "kill");
    if (!HOOKS_READY()) return _kill_fn ? _kill_fn(pid, sig) : 0;
    if (sig == 9 || sig == 15) return 0;
    return _kill_fn ? _kill_fn(pid, sig) : 0;
}

/* ---- exit_group hook — block only if caller is in target module ---- */
typedef void (*exit_group_t)(int);
static exit_group_t _exit_group = NULL;
/* g_ts_text_start/end declared at line 744 */

void exit_group(int status) {
    if (!_exit_group) _exit_group = (exit_group_t)dlsym(RTLD_NEXT, "exit_group");
    /* [v7.0 Patch B] exit_group — 无论 g_hooks_ready 状态都检查 return address
     * 原版: g_hooks_ready=0 时直接透传，hijack 模式下 tersafe 在 hooks 激活前
     * 就能通过 exit_group 杀死进程。修复：始终检查调用方地址范围。*/
    if (g_ts_text_start) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0);
        if (ra >= g_ts_text_start && ra < g_ts_text_end) {
            hook_log("[exit_group] blocked (tersafe caller)\n");
            return;
        }
    } else if (!HOOKS_READY()) {
        /* tersafe 地址范围未知且 hooks 未激活，透传 */
        if (_exit_group) _exit_group(status);
        return;
    }
    /* Cache target module code segment range */
    if (!g_ts_text_start) {
        g_ts_text_start = get_module_base(C_tersafe);
        if (g_ts_text_start) {
            int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDONLY, 0);
            if (fd >= 0) {
                /* ELF64 header: e_phoff at offset 32(8 bytes), e_phnum at offset 56(2 bytes) */
                syscall(__NR_lseek, fd, (off_t)(g_ts_text_start + 32), SEEK_SET);
                uint64_t phoff = 0; uint16_t phnum = 0;
                syscall(SYS_read, fd, &phoff, 8);
                syscall(__NR_lseek, fd, (off_t)(g_ts_text_start + 56), SEEK_SET);
                syscall(SYS_read, fd, &phnum, 2);
                /* scan program headers for PT_LOAD with execute permission */
                for (int i = 0; i < phnum && i < 32; i++) {
                    uint32_t ph[2]; /* p_type + p_flags */
                    uint64_t p_vaddr, p_memsz;
                    off_t ph_addr = (off_t)(g_ts_text_start + phoff + i * 56);
                    syscall(__NR_lseek, fd, ph_addr, SEEK_SET);
                    syscall(SYS_read, fd, ph, 8);
                    syscall(__NR_lseek, fd, ph_addr + 16, SEEK_SET);
                    syscall(SYS_read, fd, &p_vaddr, 8);
                    syscall(__NR_lseek, fd, ph_addr + 40, SEEK_SET);
                    syscall(SYS_read, fd, &p_memsz, 8);
                    if (ph[1] & 1) { /* PF_X */
                        g_ts_text_end = g_ts_text_start + p_vaddr + p_memsz;
                        break;
                    }
                }
                syscall(SYS_close, fd);
            }
            if (!g_ts_text_end) g_ts_text_end = g_ts_text_start + 0x600000; /* fallback 6MB */
        }
    }
    /* Check if return address is in target module code range */
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (g_ts_text_start && ra >= g_ts_text_start && ra < g_ts_text_end) {
        hook_log("[exit_group] blocked target module call\n");
        return; /* 吃掉，不执行 */
    }
    if (_exit_group) _exit_group(status);
    /* 不应到达这里 */
    for (;;) syscall(ARM64_NR_EXIT_GROUP, status);
}

/* ---- getenv hook — filter environment variable probes ---- */
typedef char *(*getenv_t)(const char *);
static getenv_t _getenv = NULL;

char *getenv(const char *name) {
    if (!_getenv) _getenv = (getenv_t)dlsym(RTLD_NEXT, "getenv");
    if (!HOOKS_READY()) return _getenv ? _getenv(name) : NULL;
    if (name && (strcmp(name, "LD_PRELOAD") == 0 ||
                 strcmp(name, "LD_LIBRARY_PATH") == 0 ||
                 strcmp(name, "ANDROID_ROOT") == 0))
        return NULL;
    return _getenv ? _getenv(name) : NULL;
}

/* ---- dl_iterate_phdr hook — filter library enumeration ---- */
typedef int (*dl_iterate_phdr_t)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
static dl_iterate_phdr_t _dl_iterate_phdr = NULL;

struct _phdr_wrap { int (*cb)(struct dl_phdr_info *, size_t, void *); void *data; };

static int _phdr_filter(struct dl_phdr_info *info, size_t size, void *arg) {
    struct _phdr_wrap *w = (struct _phdr_wrap *)arg;
    if (info && info->dlpi_name &&
        (strstr(info->dlpi_name, C_forgehook) ||
         strstr(info->dlpi_name, C_forgehook_real)))
        return 0;
    return w->cb(info, size, w->data);
}

int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!_dl_iterate_phdr)
        _dl_iterate_phdr = (dl_iterate_phdr_t)dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if (!_dl_iterate_phdr) return 0;
    if (!HOOKS_READY()) return _dl_iterate_phdr(cb, data);
    struct _phdr_wrap w = {cb, data};
    return _dl_iterate_phdr(_phdr_filter, &w);
}

/* ---- dlopen hook — prevent probing of instrumentation library ---- */
typedef void *(*dlopen_t)(const char *, int);
static dlopen_t _dlopen_real = NULL;

void *dlopen(const char *filename, int flags) {
    if (!_dlopen_real)
        _dlopen_real = (dlopen_t)dlsym(RTLD_NEXT, "dlopen");
    /* 关键修复: hijack 模式下 libtdmqimei.so 是我们的 so。
     * 如果 tersafe/其他库 dlopen("libtdmqimei.so") 然后 dlsym 查找
     * qimei 符号，会返回 NULL（我们的 so 不导出原版符号）。
     * 重定向到 chainloaded 原版 handle 解决此问题。 */
    if (filename && strstr(filename, C_qimei) &&
        !strstr(filename, C_forgehook_real) && g_real_qimei_handle) {
        if (flags & RTLD_NOLOAD) return g_real_qimei_handle;  /* 探测 → 返回原版 */
        return g_real_qimei_handle;  /* 直接返回 chainloaded handle */
    }
    if (!HOOKS_READY()) return _dlopen_real ? _dlopen_real(filename, flags) : NULL;
    if (filename) {
        if (strstr(filename, C_forgehook) ||
            strstr(filename, C_forgehook_real) ||
            strstr(filename, "frida") ||
            strstr(filename, "xposed") ||
            strstr(filename, "substrate")) {
            if (flags & RTLD_NOLOAD) return NULL;  /* 探测 → 不存在 */
            /* 不是 NOLOAD → 可能是合法加载，放过 */
        }
    }
    return _dlopen_real ? _dlopen_real(filename, flags) : NULL;
}

/* ---- P1: dlsym hook — REMOVED (recursive: dlsym→self→stack overflow)
 * All hooks use dlsym(RTLD_NEXT) for resolution; hooking dlsym itself
 * creates infinite recursion when _dlsym_real is NULL. The hook was a
 * no-op passthrough anyway — no symbol filtering was implemented. ---- */
#if 0  /* dead code preserved for reference — DO NOT re-enable */
typedef void *(*dlsym_t)(void *, const char *);
static dlsym_t _dlsym_real = NULL;

void *dlsym(void *handle, const char *symbol) {
    if (!_dlsym_real)
        _dlsym_real = (dlsym_t)dlsym(RTLD_NEXT, "dlsym");
    if (!_open) return _dlsym_real(handle, symbol);
    return _dlsym_real ? _dlsym_real(handle, symbol) : NULL;
}
#endif

/* ---- dladdr hook — normalize library origin ---- */
typedef int (*dladdr_t)(const void *, Dl_info *);
static dladdr_t _dladdr_real = NULL;

int dladdr(const void *addr, Dl_info *info) {
    if (!_dladdr_real)
        _dladdr_real = (dladdr_t)dlsym(RTLD_NEXT, "dladdr");
    if (!_dladdr_real) return 0;
    if (!HOOKS_READY()) return _dladdr_real(addr, info);
    int rc = _dladdr_real(addr, info);
    if (rc && info && info->dli_fname) {
        if (strstr(info->dli_fname, C_forgehook) ||
            strstr(info->dli_fname, C_forgehook_real)) {
            info->dli_fname = "libc.so";
            info->dli_fbase = NULL;
        }
    }
    return rc;
}

/* ---- P0ext: opendir / readdir — 目录级隐藏 ---- */
typedef DIR  *(*opendir_t)(const char *);
typedef struct dirent *(*readdir_t)(DIR *);
static opendir_t _opendir = NULL;
static readdir_t _readdir = NULL;

static const char *FILT_NAMES[] = {
    "frida", "gdbserver", "gdb", "magisk", ".magisk", "supersu",
    "xposed", "lsposed", "edxposed", "substrate",
    "qemu", "vbox", "vhost", "goldfish", "libdroid4x",
    "nox", "ttVM", "androVM", "microvirt", "droid4x",
    "nemud", "genymotion", "windroye", "bluestacks",
    NULL
};

static int dname_filtered(const char *n) {
    if (!n) return 0;
    for (const char **p = FILT_NAMES; *p; p++)
        if (strstr(n, *p)) return 1;
    return 0;
}

DIR *opendir(const char *name) {
    if (!_opendir) _opendir = (opendir_t)dlsym(RTLD_NEXT, "opendir");
    if (!HOOKS_READY()) return _opendir ? _opendir(name) : NULL;
    if (hidden(name)) { errno = ENOENT; return NULL; }
    return _opendir ? _opendir(name) : NULL;
}

struct dirent *readdir(DIR *dirp) {
    if (!_readdir) _readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");
    if (!_readdir) return NULL;
    if (!HOOKS_READY()) return _readdir(dirp);
    struct dirent *ent;
    while ((ent = _readdir(dirp)) != NULL) {
        if (!dname_filtered(ent->d_name)) break;
    }
    return ent;
}

/* readdir64 — 64-bit directory enumeration filter */
typedef struct dirent64 *(*readdir64_t)(DIR *);
static readdir64_t _readdir64 = NULL;

struct dirent64 *readdir64(DIR *dirp) {
    if (!_readdir64) _readdir64 = (readdir64_t)dlsym(RTLD_NEXT, "readdir64");
    if (!_readdir64) return NULL;
    if (!HOOKS_READY()) return _readdir64(dirp);
    struct dirent64 *ent;
    while ((ent = _readdir64(dirp)) != NULL) {
        if (!dname_filtered(ent->d_name)) break;
    }
    return ent;
}

/* ---- r_debug link_map filter — remove instrumentation from linker list ---- */
/* Inline r_debug / link_map structs for build compatibility */
struct my_link_map {
    uintptr_t l_addr;
    char     *l_name;
    void     *l_ld;
    struct my_link_map *l_next;
};
struct my_r_debug {
    int r_version;
    struct my_link_map *r_map;
};

__attribute__((constructor(101)))
static void _hide_from_linker_list(void) {
    hook_log("[CTOR] 101 _hide_from_linker_list enter\n");
    struct my_r_debug *dbg = (struct my_r_debug *)dlsym(RTLD_DEFAULT, "_r_debug");
    if (!dbg) dbg = (struct my_r_debug *)dlsym(RTLD_DEFAULT, "__r_debug");
    if (!dbg || !dbg->r_map) { hook_log("[CTOR] 101 no r_debug found\n"); return; }

    struct my_link_map *prev = NULL, *cur = dbg->r_map;
    int removed = 0;
    while (cur && removed < 2) {
        const char *name = cur->l_name;
        if (name && name[0] && (strstr(name, C_forgehook) ||
                                 strstr(name, C_forgehook_real))) {
            if (prev) prev->l_next = cur->l_next;
            else     dbg->r_map   = cur->l_next;
            hook_log("[r_debug] unlinked from linker list\n");
            removed++;
            cur = prev ? prev->l_next : dbg->r_map;
            continue;
        }
        prev = cur;
        cur = cur->l_next;
    }
    hook_log("[CTOR] 101 _hide_from_linker_list done\n");
}

/* ---- getaddrinfo hook — DNS resolution filter ---- */
typedef int (*getaddrinfo_t)(const char *, const char *,
                             const void *, void *);
static getaddrinfo_t _getaddrinfo = NULL;

static const char *AC_DOMAINS[] = {
    "tdm.qq.com", "tdm.3g.qq.com", "crashsight.qq.com",
    "gcloud.tencent.com", "report.qq.com", "stat.qq.com",
    "cloud.tencent.com", "gamelobby.qq.com", "igame.qq.com",
    "qimei.qq.com", "snowflake.qq.com", "tpns.qq.com",
    "beacon.qq.com", "bugly.qq.com",
    NULL
};

int getaddrinfo(const char *node, const char *service,
                const void *hints, void *res) {
    if (!_getaddrinfo)
        _getaddrinfo = (getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
    if (!HOOKS_READY()) return _getaddrinfo ? _getaddrinfo(node, service, hints, res) : -2;
    if (node) {
        for (const char **d = AC_DOMAINS; *d; d++) {
            if (strstr(node, *d)) {
                hook_log("[net] blocked getaddrinfo\n");
                return -2; /* EAI_NONAME */
            }
        }
    }
    return _getaddrinfo ? _getaddrinfo(node, service, hints, res) : -2;
}

/* ---- connect hook — IP-level connection filter ---- */
typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
static connect_t _connect_orig = NULL;

/* Known analytics server IP prefixes */
static int is_ac_ip(const struct sockaddr *addr) {
    if (!addr || addr->sa_family != AF_INET)
        return 0;
    uint32_t ip = ((const struct sockaddr_in *)addr)->sin_addr.s_addr;
    static const uint32_t kACNets[] = {
        0x6DEF7700u, /* 118.239.119.x */
        0x3BA8A800u, /* 59.168.168.x */
        0x197B1900u, /* 123.25.25.x */
        0x2D760B00u, /* 45.118.11.x */
        0x6BEF7100u, /* 107.239.113.x */
        0
    };
    for (const uint32_t *n = kACNets; *n; n++) {
        if ((ip & 0xFFFFFF00u) == (*n & 0xFFFFFF00u)) return 1;
    }
    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!_connect_orig)
        _connect_orig = (connect_t)dlsym(RTLD_NEXT, "connect");
    if (!HOOKS_READY()) return _connect_orig ? _connect_orig(sockfd, addr, addrlen) : -1;
    if (is_ac_ip(addr)) {
        hook_log("[net] blocked connect to AC IP\n");
        errno = ECONNREFUSED;
        return -1;
    }
    return _connect_orig ? _connect_orig(sockfd, addr, addrlen) : -1;
}

/* ---- GLES/EGL hook — GPU renderer string normalization ---- */
/* Use raw type declarations for build independence */
/* DISABLED (v6.1): GPU hook removed — cloud phone virtual GPU doesn't match
 * fake Adreno 730 strings. Returning mismatched GPU caps to UE4's renderer
 * causes EGL/GLES initialization failure → permanent black screen.
 *
 * Original approach: patch_branch on glGetString/eglQueryString to return
 * "Adreno (TM) 730" / "Qualcomm". But if the actual GPU is Mali or a
 * virtualized GPU with different feature bits, the UE4 RHI layer queries
 * GL_EXTENSIONS/GL_RENDERER, gets capabilities for Adreno 730, tries to
 * use Adreno-specific extensions → fails → renderer stuck at init.
 *
 * Correct fix (TODO): query actual GPU caps at runtime, generate matching
 * fake strings. Or use GPU-specific overrides per cloud phone model. */
__attribute__((constructor(120)))
static void _patch_gpu_driver(void) {
    hook_log("[CTOR] 120 _patch_gpu_driver SKIPPED (disabled — mismatched GPU caps)\n");
}

/* ============================================================
 * Target module runtime patching - constructor(150)
 *
 * Process termination chain interception (based on crash analysis):
 *   entry -> 0x419fdc -> 0x2e7810(dispatch) -> 0x2f29d0(router) ->
 *   0x320d78(wrapper) -> 0x3233b8(syscall)
 *
 * Strategy: intercept all nodes in the termination chain.
 * Timing: poll-wait for target module load (constructor may run before
 * the module is loaded when using library hijack injection).
 * ============================================================ */

/* [v7.1] hook_log — 使用加密路径 + 0666 权限确保 app 进程可写 */
static void hook_log(const char *msg) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD,
        C_forgehook_log,
        O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) {
        /* fallback: /sdcard 权限宽松 */
        fd = (int)syscall(SYS_openat, AT_FDCWD,
            "/sdcard/forge_hook.log",
            O_WRONLY | O_CREAT | O_APPEND, 0666);
    }
    if (fd < 0) return;
    size_t len = 0; while (msg[len]) len++;
    (void)syscall(SYS_write, fd, msg, len);
    syscall(SYS_close, fd);
}

static uintptr_t get_module_base(const char *so_name) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, C_maps_path, O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[32768];
    ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *line = buf;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        if (strstr(line, so_name)) {
            uintptr_t base = (uintptr_t)strtoul(line, NULL, 16);
            if (eol) *eol = '\n';
            return base;
        }
        if (!eol) break;
        *eol = '\n';
        line = eol + 1;
    }
    return 0;
}

/* AArch64 single-instruction patch
 * Method 1: mprotect RWX (Android <=9 or permissive SELinux)
 * Method 2: pwrite64 via /proc/self/mem (runtime code update, Android 10+ preferred) */
static int patch_insn(uintptr_t addr, uint32_t insn) {
    uintptr_t page   = addr & ~(uintptr_t)(4096 - 1);
    size_t    pagesz = (addr & 4095) > 4092 ? 8192 : 4096;
    if (syscall(SYS_mprotect, (void *)page, pagesz,
                PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(volatile uint32_t *)addr = insn;
        __builtin___clear_cache((void *)addr, (void *)(addr + 4));
        syscall(SYS_mprotect, (void *)page, pagesz, PROT_READ | PROT_EXEC);
        return 0;
    }
    int mfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDWR, 0);
    if (mfd < 0) return -2;
    ssize_t nw = (ssize_t)syscall(__NR_pwrite64, mfd, &insn, (size_t)4, (off_t)addr);
    syscall(SYS_close, mfd);
    if (nw != 4) return -3;
    __builtin___clear_cache((void *)addr, (void *)(addr + 4));
    return 0;
}

/* termination chain patch table - ordered from entry to syscall
 * v8.1: 多指令序列特征扫描，跨版本鲁棒性提升
 * 回退链: 硬编码偏移 → seq多指令扫描 → sig单指令扫描 */
static const struct {
    uint64_t    off;           /* 硬编码 patch 偏移 */
    uint32_t    insn;          /* patch 后目标指令 */
    const char *name;
    /* [legacy] 单指令特征 (pattern_scan4 最终回退) */
    uint32_t    sig_bytes[4];  int sig_len;
    /* [v8.1] 多指令序列特征 (pattern_scan_seq，更鲁棒) */
    uint32_t    seq_insns[4];  uint32_t seq_masks[4];
    int         seq_len;       /* 0=未填，跳过序列扫描 */
    int         seq_delta;     /* 序列首条指令到 patch 点的字节偏移 */
} kKillChain[] = {
    /* Node 1: detect_entry — MOV X0,#0
     * 序列: str w0,[sp,#0xc](exact) → bl(mask) → bl→patch ; delta=8 */
    {0x419fdcu, 0xD2800000u, "detect_entry MOV X0,#0",
     {0x97FB3560u}, 1,
     {0xb9000fe0u, 0x94000000u, 0x94000000u, 0u},
     {0xFFFFFFFFu, 0xFC000000u, 0xFC000000u, 0u},
     3, 8},
    /* Node 2: detect_entry+4 — RET
     * 序列: bl(mask) → b+1(exact)→patch ; delta=4 */
    {0x419fe0u, 0xD65F03C0u, "detect_entry+4 RET",
     {0x14000001u}, 1,
     {0x94000000u, 0x14000001u, 0u, 0u},
     {0xFC000000u, 0xFFFFFFFFu, 0u, 0u},
     2, 4},
    /* Node 3: kill_dispatch — RET
     * 序列: tbz w8,#0,+X(mask offset) → b+1(exact) → bl→patch ; delta=8 */
    {0x2e7810u, 0xD65F03C0u, "kill_dispatch RET",
     {0x9400100Bu}, 1,
     {0x36000000u, 0x14000001u, 0x94000000u, 0u},
     {0xFFF8001Fu, 0xFFFFFFFFu, 0xFC000000u, 0u},
     3, 8},
    /* Node 4: kill_router — RET
     * 序列: strb w8,[sp](exact) → b(mask) → bl(mask) → bl→patch ; delta=12 */
    {0x2f29d0u, 0xD65F03C0u, "kill_router RET",
     {0x9400B8BAu}, 1,
     {0x390003e8u, 0x14000000u, 0x94000000u, 0x94000000u},
     {0xFFFFFFFFu, 0xFC000000u, 0xFC000000u, 0xFC000000u},
     4, 12},
    /* Node 5: kill_wrapper — RET
     * 序列: b(mask) → adrp x8(mask imm) → ldr w1,[x8,any](mask imm12) → bl→patch ; delta=12 */
    {0x320d78u, 0xD65F03C0u, "kill_wrapper RET",
     {0x940008BFu}, 1,
     {0x14000000u, 0x90000008u, 0xB9400101u, 0x94000000u},
     {0xFC000000u, 0x9F00001Fu, 0xFFC003FFu, 0xFC000000u},
     4, 12},
    /* Node 6: tgkill_call — RET
     * 序列: stp Wt,?,[sp,any](mask Rt2+imm7) → br x16(exact) → ldrb post-idx(mask reg+imm)→patch
     * br x16 是最强锚点(ARM64 ABI intra-call scratch)，抗寄存器重分配; delta=8 */
    {0x3233b8u, 0xD65F03C0u, "tgkill_call RET",
     {0x3840140Fu}, 1,
     {0x29013feeu, 0xd61f0200u, 0x38000401u, 0u},
     {0xFFC003FFu, 0xFFFFFFFFu, 0xFF200C00u, 0u},
     3, 8},
};
#define KILL_CHAIN_N (sizeof(kKillChain)/sizeof(kKillChain[0]))

/* ---- pattern scan — 跨版本自动定位补丁偏移 ---- */
/* 在 [base, base+max_scan) 范围内搜索 4 字节 pattern。
 * 用于目标模块更新后自动重新定位检测链节点。
 * 返回匹配偏移 (相对 base)，0 表示未找到。 */
static uint64_t pattern_scan4(uintptr_t base, uint32_t pattern, size_t max_scan) {
    if (!base || max_scan < 4) return 0;
    /* 读 ELF 头获取 .text 段实际大小 */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDONLY, 0);
    if (fd < 0) return 0;
    /* 简单线性扫描，每 4 字节对齐 */
    for (size_t off = 0; off < max_scan - 3; off += 4) {
        uint32_t val = 0;
        /* 直接用 syscall 读内存 (比 /proc/self/mem 慢但更可靠) */
        if (syscall(__NR_pread64, fd, &val, 4, (off_t)(base + off)) != 4) continue;
        if (val == pattern) {
            syscall(SYS_close, fd);
            return (uint64_t)off;
        }
    }
    syscall(SYS_close, fd);
    return 0;
}

/* [v8 NEW-4] pattern_scan_seq — 多指令序列扫描 (带掩码)
 * 比 pattern_scan4 更鲁棒：支持 n 条指令序列 + 每条独立掩码。
 * 可以掩掉 BL/B 指令的相对偏移字段，只匹配 opcode 高位。
 * 返回序列第一条指令的 offset (相对 base)，0 表示未找到。
 *
 * insns[i]: 目标指令值; masks[i]: 比较掩码 (0=通配)
 * sig_delta: 序列匹配位置到 patch 点的字节偏移 */
static uint64_t pattern_scan_seq(uintptr_t base,
                                  const uint32_t *insns,
                                  const uint32_t *masks,
                                  int n, size_t max_scan,
                                  int sig_delta) {
    if (!base || n <= 0 || !insns || max_scan < (size_t)(n * 4)) return 0;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDONLY, 0);
    if (fd < 0) return 0;
    for (size_t off = 0; off + (size_t)(n * 4) <= max_scan; off += 4) {
        int match = 1;
        for (int k = 0; k < n && match; k++) {
            uint32_t val = 0;
            if (syscall(__NR_pread64, fd, &val, 4,
                        (off_t)(base + off + (size_t)(k * 4))) != 4) {
                match = 0; break;
            }
            uint32_t m = masks ? masks[k] : 0xFFFFFFFFu;
            if ((val & m) != (insns[k] & m)) match = 0;
        }
        if (match) {
            syscall(SYS_close, fd);
            return (uint64_t)((int64_t)off + sig_delta);
        }
    }
    syscall(SYS_close, fd);
    return 0;
}

/* [v8.1] 回退链: 硬编码偏移 → 多指令序列扫描 → 单指令扫描 */
static uint64_t resolve_patch_offset(uintptr_t base, uint64_t hard_off,
    uint32_t expected_insn,
    const uint32_t *sig, int sig_len,
    const uint32_t *seq_insns, const uint32_t *seq_masks,
    int seq_len, int seq_delta)
{
    /* 1. 验证硬编码偏移 */
    uint32_t cur = 0;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDONLY, 0);
    if (fd >= 0) {
        syscall(__NR_pread64, fd, &cur, 4, (off_t)(base + hard_off));
        syscall(SYS_close, fd);
    }
    if (cur == expected_insn) return hard_off;

    /* 2. 多指令序列扫描 (跨版本首选) */
    if (seq_insns && seq_len > 0) {
        uint64_t found = pattern_scan_seq(base, seq_insns, seq_masks,
                                          seq_len, 0x600000, seq_delta);
        if (found) {
            hook_log("[scan] seq-match OK\n");
            return found;
        }
    }

    /* 3. 单指令扫描最终回退 */
    if (sig && sig_len > 0) {
        for (int i = 0; i < sig_len; i++) {
            uint64_t found = pattern_scan4(base, sig[i], 0x400000);
            if (found) {
                hook_log("[scan] sig4 fallback OK\n");
                return found;
            }
        }
    }

    hook_log("[scan] WARNING: all fallbacks failed, using hard offset\n");
    return hard_off;
}

/* ---- background thread: poll + patch target module ---- */
static void *_adjust_code_thread(void *unused) {
    (void)unused;
    uintptr_t base = 0;
    char logbuf[160];

    /* [v7.0 P1-1] 后台线程中先执行 chainload，linker 锁已释放 */
    pthread_once(&g_chainload_once, _do_chainload);

    /* [v7.1 Fix 1] 30s 超时看门狗 — 独立线程，不受主 patch 流程阻塞影响 */
    static time_t g_watchdog_start = 0;
    g_watchdog_start = time(NULL);

    /* poll-wait for target module (up to 60 seconds), detached thread */
    for (int retry = 0; retry < 300; retry++) {
        base = get_module_base(C_tersafe);
        if (base) break;
        if (retry == 0) hook_log("[patch] waiting for target module...\n");
        /* [v7.1 Fix 1] 超时看门狗: 30s 未找到 tersafe 也激活 hook */
        if (retry >= 150 && !HOOKS_READY() && time(NULL) - g_watchdog_start > 30) {
            __atomic_store_n(&g_hooks_ready, 1, __ATOMIC_RELEASE);
            hook_log("[hooks] v7.1 activated (30s watchdog)\n");
        }
        usleep(200000);
    }
    if (!base) {
        hook_log("[patch] TIMEOUT: target module not loaded after 60s\n");
        /* 超时兜底激活 */
        __atomic_store_n(&g_hooks_ready, 1, __ATOMIC_RELEASE);
        hook_log("[hooks] v7.1 activated (60s timeout)\n");
        return NULL;
    }
    /* [v7.0 P0-1] 先缓存 tersafe 代码段范围供 tgkill/exit_group 使用 */
    g_ts_text_start = base;
    g_ts_text_end   = base + 0x600000; /* 6MB 保守估计，后续由 exit_group 精确化 */
    int ln = snprintf(logbuf, sizeof(logbuf),
        "[patch] base=0x%lx\n", (unsigned long)base);
    if (ln > 0) hook_log(logbuf);

    int ok = 0;
    for (size_t i = 0; i < KILL_CHAIN_N; i++) {
        uint64_t off = resolve_patch_offset(base, kKillChain[i].off,
            kKillChain[i].insn,
            kKillChain[i].sig_bytes, kKillChain[i].sig_len,
            kKillChain[i].seq_insns, kKillChain[i].seq_masks,
            kKillChain[i].seq_len,   kKillChain[i].seq_delta);
        int r = patch_insn(base + off, kKillChain[i].insn);
        ln = snprintf(logbuf, sizeof(logbuf),
            "[patch] %-28s off=0x%06llx r=%d\n",
            kKillChain[i].name, (unsigned long long)off, r);
        if (ln > 0) hook_log(logbuf);
        if (r == 0) ok++;
    }
    ln = snprintf(logbuf, sizeof(logbuf),
        "[patch] done: %d/%zu ok\n", ok, KILL_CHAIN_N);
    if (ln > 0) hook_log(logbuf);

    /* [v7.1 Fix 1] 多路径 hook 激活 — 防止任何场景下 hooks 永不被激活
     *
     * v7.0 致命 bug: 仅一条激活路径 (ok >= KILL_CHAIN_N - 2)。
     * tersafe 持续恢复补丁时，_adjust_code_thread 的一次性检查
     * 可能恰好遇到 ok<4 → 等 2s 后 force-activate。但如果进程在这 2s
     * 内被杀（tersafe 已恢复检测链并调用了 tgkill），hooks 永不被激活。
     *
     * v7.1 三路径:
     *   A) patch 成功 → 立即激活
     *   B) inject 模式 (base!=0, 游戏已加载) → 立即激活
     *   C) 超时兜底 30s → 无论如何激活
     *
     * 关键认知: inject 模式下游戏已完全初始化，即使代码补丁失败，
     * 至少文件伪装+属性 hook 必须工作，否则封号。完美防护 > 无防护。 */
    const int need_ok = (int)KILL_CHAIN_N - 2;

    /* 路径 A: patch 成功 */
    if (ok >= need_ok) {
        __atomic_store_n(&g_hooks_ready, 1, __ATOMIC_RELEASE);
        hook_log("[hooks] v7.1 activated (patch ok=");
    }
    /* 路径 B: inject 模式 — tersafe 已加载说明游戏初始化完成 */
    else if (base != 0) {
        __atomic_store_n(&g_hooks_ready, 1, __ATOMIC_RELEASE);
        hook_log("[hooks] v7.1 activated (inject mode, tersafe loaded) ok=");
    }
    /* 路径 C: 补丁全部失败 — 等 2s 重试一次，再失败也激活 */
    else {
        usleep(2000000);
        int ok2 = 0;
        for (size_t i = 0; i < KILL_CHAIN_N; i++) {
            uint64_t off = resolve_patch_offset(base, kKillChain[i].off,
                kKillChain[i].insn,
                kKillChain[i].sig_bytes, kKillChain[i].sig_len,
                kKillChain[i].seq_insns, kKillChain[i].seq_masks,
                kKillChain[i].seq_len,   kKillChain[i].seq_delta);
            if (patch_insn(base + off, kKillChain[i].insn) == 0) ok2++;
        }
        __atomic_store_n(&g_hooks_ready, 1, __ATOMIC_RELEASE);
        hook_log("[hooks] v7.1 activated (retry) ok2=");
    }
    /* 记录最终 ok 数 */
    {
        char okbuf[32]; int okl = snprintf(okbuf, sizeof(okbuf), "%d\n", ok);
        if (okl > 0) hook_log(okbuf);
    }

    /* [v7.1 Fix 1 续] 30s 超时兜底 — 无论上述路径如何，30 秒后必须激活。
     * 在 _adjust_code_thread 被阻塞（如 dlopen 等待锁）的情况下
     * 确保 hook 不会永久失效。此逻辑在函数开头，与上述路径独立。 */
    static time_t g_thread_start_time = 0;
    if (!g_thread_start_time) g_thread_start_time = time(NULL);

    return NULL;
}

__attribute__((constructor(150)))
static void _adjust_code(void) {
    hook_log("[CTOR] 150 _adjust_code enter\n");
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, _adjust_code_thread, NULL) != 0) {
        hook_log("[patch] FATAL: pthread_create failed, patching inline...\n");
        _adjust_code_thread(NULL);
    }
    pthread_attr_destroy(&attr);
    /* [v7.0 P0-1] 移除 constructor(150) 内的提前激活
     * g_hooks_ready=1 已移至 _adjust_code_thread patch 完成后设置。
     * inject 模式: 线程几乎立即找到 tersafe 并 patch，延迟<1s
     * hijack 模式: 等 tersafe 加载后 patch，消除检测窗口 */
    hook_log("[CTOR] 150 _adjust_code done (hooks activate after patch)\n");
}

/* ---- seccomp-bpf SIGSYS handler ---- */
static volatile int g_bpf_active=0;
static volatile uint64_t g_sigsys_total=0;
static volatile uint64_t g_sigsys_blocked=0;

static int get_sigsys_regs(ucontext_t *uc,uint64_t *x0,uint64_t *x1,uint64_t *x2){
    uint64_t *raw=(uint64_t*)&uc->uc_mcontext;
    *x0=raw[1];*x1=raw[2];*x2=raw[3];
    return 0;
}
static void set_sigsys_x0(ucontext_t *uc,uint64_t val){
    uint64_t *raw=(uint64_t*)&uc->uc_mcontext;
    raw[1]=val;
}

static void sigsys_handler(int sig,siginfo_t *info,void *ucontext){
    g_sigsys_total++;
    ucontext_t *uc=(ucontext_t*)ucontext;
    uint64_t x0,x1,x2;
    get_sigsys_regs(uc,&x0,&x1,&x2);
    char path[512];
    if(safe_read_path(x1,path,sizeof(path))!=0){set_sigsys_x0(uc,(uint64_t)-ENOSYS);return;}
    if(hidden(path)){set_sigsys_x0(uc,(uint64_t)-ENOENT);g_sigsys_blocked++;return;}
    if(is_virtio_path(path)){set_sigsys_x0(uc,(uint64_t)-ENOENT);g_sigsys_blocked++;return;}
    const override_file_t *ff=match(path);
    if(ff&&!(x2&1)){int fd=override_fd(ff->data,ff->len);if(fd>=0){set_sigsys_x0(uc,(uint64_t)fd);g_sigsys_blocked++;return;}}
    set_sigsys_x0(uc,(uint64_t)-ENOSYS);
}

/* ============================================================
 * seccomp-bpf v6.1 — exit_group only, no signal blocking
 *
 * v6.0 的 tgkill/tkill/kill 拦截导致 ART 线程管理失败闪退。
 * 检测链6节点代码调整已从源头处理进程管理逻辑，
 * BPF 只需兜底拦截 exit_group(94)。其余 syscall 全放行。
 *
 * Flow: arch→exit_group(94)→BLOCK →ALLOW all else
 * constructor priority=49. */

/* BPF helper macros — readable instruction construction */
#define BPF_STMT(code,k)        { (uint16_t)(code), 0,0, (uint32_t)(k) }
#define BPF_JUMP(code,k,jt,jf)  { (uint16_t)(code), (uint8_t)(jt), (uint8_t)(jf), (uint32_t)(k) }

static struct sock_filter g_bpf_prog[]={
    /* 0-2: architecture check — allow non-AArch64 through */
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,    4),                             /* [0] */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,    AUDIT_ARCH_AARCH64, 1, 0),     /* [1] */
    BPF_STMT(BPF_RET|BPF_K,            SECCOMP_RET_ALLOW),             /* [2] */

    /* 3: load syscall nr */
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,     0),                             /* [3] */

    /* ---- exit_group(94): hard block — fallback if libc hook misses ---- */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,    ARM64_NR_EXIT_GROUP, 0, 1),    /* [4]→[5] or skip */
    BPF_STMT(BPF_RET|BPF_K,            SECCOMP_RET_ERRNO|1),           /* [5] BLOCK exit_group */

    /* ALLOW everything else */
    BPF_STMT(BPF_RET|BPF_K,            SECCOMP_RET_ALLOW),             /* [6] */
};
/* v6.1: 7 instructions — exit_group only, tgkill/tkill/kill removed (crashed ART) */
static struct sock_fprog g_bpf_fprog={.len=sizeof(g_bpf_prog)/sizeof(g_bpf_prog[0]),.filter=g_bpf_prog};

/* DISABLED: BPF exit_group拦截，待libc exit_group hook联合启用后恢复。
 * 检测链6节点已从源头处理进程管理逻辑,BPF在这个阶段冗余。 */
__attribute__((unused))
static void install_seccomp(void){
    hook_log("[CTOR] 49 _install_seccomp_cb enter\n");
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sa.sa_sigaction=sigsys_handler;
    sa.sa_flags=SA_SIGINFO|SA_RESTART|SA_NODEFER;
    sigaction(SIGSYS,&sa,NULL);
    prctl(38,1,0,0,0);
    long r = syscall(277, 1, 1, &g_bpf_fprog);
    int used_tsync = (r == 0);
    if(r != 0) r = syscall(277, 1, 0, &g_bpf_fprog);
    g_bpf_active = (r == 0) ? 1 : 0;
    char logbuf[128];
    int ln = snprintf(logbuf, sizeof(logbuf),
        "[seccomp] v6.1 exit_group-only, r=%ld errno=%d tsync=%d active=%d\n",
        r, r!=0?errno:0, used_tsync, g_bpf_active);
    if (ln > 0) hook_log(logbuf);
    hook_log("[CTOR] 49 _install_seccomp_cb done\n");
}
/* DISABLED: BPF exit_group拦截导致inject模式下进程退出异常。
 * 检测链6节点已从源头处理进程管理逻辑，
 * BPF exit_group兜底在当前版本反而有害——恢复时需配合libc exit_group hook。 */
/* __attribute__((constructor(49))) */
__attribute__((unused))
static void _install_seccomp_cb(void){ hook_log("[CTOR] 49 seccomp SKIPPED (requires libc exit_group hook co-enablement)\n"); }

/* ---- __system_property_get hook ---- */
/* Device profile system — macro-driven, switchable at compile time.
 * Define DEVICE_PROFILE_S10 for Samsung S10, DEVICE_PROFILE_K60 for Xiaomi.
 * Default: DEVICE_PROFILE_S10 (matches beyond1q baseline). */

/* ============ DEVICE PROFILE TABLE ============
 * Each profile defines: product props, build props, security flags, network, serial
 * Add new profiles here. Use PROFILE_ENTRY(key,val) for normal, PROFILE_CLEAR(key) to blank.
 * ============================================ */
#define PROFILE_ENTRY(k,v) {k, v}
#define PROFILE_CLEAR(k)   {k, ""}
#define PROFILE_END        {NULL, NULL}

/* --- Shared device property table (used by native + JNI) --- */
typedef struct{const char *key;const char *value;}hook_prop_t;

/* Profile: Samsung Galaxy S10 (SM-G9730 beyond1q) — Android 11, Snapdragon 855 */
static const hook_prop_t HOOK_PROPS[]={
    /* product identity */
    PROFILE_ENTRY("ro.product.manufacturer","samsung"),
    PROFILE_ENTRY("ro.product.model","SM-G9730"),
    PROFILE_ENTRY("ro.product.device","beyond1q"),
    PROFILE_ENTRY("ro.product.name","beyond1qltezc"),
    PROFILE_ENTRY("ro.build.product","beyond1q"),
    PROFILE_ENTRY("ro.product.brand","samsung"),
    PROFILE_ENTRY("ro.hardware","qcom"),
    PROFILE_ENTRY("ro.board.platform","msmnile"),
    PROFILE_ENTRY("ro.product.board","msmnile"),
    /* build fingerprint */
    PROFILE_ENTRY("ro.build.fingerprint","samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"),
    PROFILE_ENTRY("ro.build.tags","release-keys"),
    PROFILE_ENTRY("ro.build.type","user"),
    PROFILE_ENTRY("ro.build.user","dpi"),
    PROFILE_ENTRY("ro.build.host","SWDD6847"),
    PROFILE_ENTRY("ro.build.description","beyond1qltezc-user 11 RP1A.200720.012 G9730ZCS6FULZ release-keys"),
    PROFILE_ENTRY("ro.build.version.sdk","30"),
    PROFILE_ENTRY("ro.build.version.release","11"),
    PROFILE_ENTRY("ro.build.version.incremental","G9730ZCS6FULZ"),
    PROFILE_ENTRY("ro.build.display.id","RP1A.200720.012.G9730ZCS6FULZ"),
    PROFILE_ENTRY("ro.product.build.id","RP1A.200720.012"),
    PROFILE_ENTRY("ro.build.flavor","beyond1qltezc-user"),
    PROFILE_ENTRY("ro.product.build.fingerprint","samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"),
    /* security flags */
    PROFILE_ENTRY("ro.debuggable","0"),
    PROFILE_ENTRY("ro.secure","1"),
    PROFILE_ENTRY("ro.adb.secure","1"),
    PROFILE_ENTRY("ro.allow.mock.location","0"),
    PROFILE_ENTRY("ro.boot.verifiedbootstate","green"),
    PROFILE_ENTRY("ro.boot.veritymode","enforcing"),
    PROFILE_ENTRY("ro.boot.flash.locked","1"),
    /* hardware */
    PROFILE_ENTRY("ro.boot.hardware","qcom"),
    PROFILE_ENTRY("ro.boot.bootloader","unknown"),
    PROFILE_ENTRY("ro.bootmode","unknown"),
    PROFILE_ENTRY("ro.kernel.qemu",""),
    PROFILE_ENTRY("ro.boot.qemu",""),
    /* network / device name */
    PROFILE_ENTRY("gsm.version.baseband","G9730ZCS6FULZ"),
    PROFILE_ENTRY("persist.sys.usb.config","adb"),
    PROFILE_ENTRY("persist.sys.device_name","SM-G9730"),
    PROFILE_ENTRY("bluetooth.name","SM-G9730"),
    PROFILE_ENTRY("wifi.interface","wlan0"),
    /* serial blanking */
    PROFILE_CLEAR("ro.serialno"),
    PROFILE_CLEAR("ro.boot.serialno"),
    PROFILE_CLEAR("net.hostname"),
    /* virtualization markers — clear */
    PROFILE_CLEAR("ro.boot.qemu.avd_name"),
    PROFILE_CLEAR("ro.boot.qemu.cpuvulkan.version"),
    PROFILE_CLEAR("ro.kernel.android.qemud"),
    PROFILE_CLEAR("sys.tencent.init"),
    PROFILE_CLEAR("sys.tencent.model"),
    PROFILE_CLEAR("init.svc.vbox86-setup"),
    PROFILE_CLEAR("ro.genymotion.version"),
    PROFILE_CLEAR("persist.nox.simulator_version"),
    PROFILE_CLEAR("microvirt.memu_version"),
    PROFILE_CLEAR("nemud.player_package"),
    PROFILE_CLEAR("qemu.hw.mainkeys"),
    PROFILE_CLEAR("qemu.sf.lcd_density"),
    PROFILE_CLEAR("ro.hardware.gralloc"),
    PROFILE_CLEAR("ro.product.base_version"),
    /* odm/product fallback — clear partition-specific props */
    PROFILE_CLEAR("ro.product.odm.brand"),
    PROFILE_CLEAR("ro.product.odm.device"),
    PROFILE_CLEAR("ro.product.odm.manufacturer"),
    PROFILE_CLEAR("ro.product.odm.model"),
    PROFILE_CLEAR("ro.product.odm.name"),
    PROFILE_CLEAR("ro.product.odm_dlkm.brand"),
    PROFILE_CLEAR("ro.product.odm_dlkm.device"),
    PROFILE_CLEAR("ro.product.odm_dlkm.manufacturer"),
    PROFILE_CLEAR("ro.product.odm_dlkm.model"),
    PROFILE_CLEAR("ro.product.odm_dlkm.name"),
    PROFILE_CLEAR("ro.product.product.brand"),
    PROFILE_CLEAR("ro.product.product.device"),
    PROFILE_CLEAR("ro.product.product.manufacturer"),
    PROFILE_CLEAR("ro.product.product.model"),
    PROFILE_CLEAR("ro.product.product.name"),
    PROFILE_CLEAR("ro.product.ota.host"),
    PROFILE_CLEAR("ro.build.characteristics"),
    PROFILE_END
};

/* JNI Build field table — derived from HOOK_PROPS, subset for android.os.Build */
typedef struct{const char *name;const char *sig;const char *val;}build_field_t;
static const build_field_t BUILD_FIELDS[]={
    {"MANUFACTURER","Ljava/lang/String;","samsung"},
    {"MODEL","Ljava/lang/String;","SM-G9730"},
    {"BRAND","Ljava/lang/String;","samsung"},
    {"DEVICE","Ljava/lang/String;","beyond1q"},
    {"PRODUCT","Ljava/lang/String;","beyond1qltezc"},
    {"HARDWARE","Ljava/lang/String;","qcom"},
    {"BOARD","Ljava/lang/String;","msmnile"},
    {"FINGERPRINT","Ljava/lang/String;","samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"},
    {"TAGS","Ljava/lang/String;","release-keys"},
    {"TYPE","Ljava/lang/String;","user"},
    {"USER","Ljava/lang/String;","dpi"},
    {"HOST","Ljava/lang/String;","SWDD6847"},
    {"DISPLAY","Ljava/lang/String;","RP1A.200720.012.G9730ZCS6FULZ"},
    {"BOOTLOADER","Ljava/lang/String;","unknown"},
    {"RADIO","Ljava/lang/String;","G9730ZCS6FULZ"},
    /* SERIAL 保持原值，空串会导致某些游戏退出 */
    {NULL,NULL,NULL}
};

typedef int (*hook_prop_get_t)(const char*,char*);
static hook_prop_get_t real_prop_get=NULL;

/* [v7.1 P4] 属性查询流量混淆
 * 防: 游戏通过查询频率/顺序指纹识别注入（正常游戏不会每秒查同一属性3次以上）。
 * 方案:
 *   1. 对非白名单属性: 缓存第一次真实值，后续直接返回缓存（延迟取一次）
 *   2. 同一属性在 1s 内查询 >3 次: 返回抖动值（尾字符 ±1 或大小写变化）
 *      注: HOOK_PROPS 已覆盖的白名单属性不受抖动影响（固定返回伪造值）
 *   3. forge_audit 改为只记录从未出现过的属性（减少 I/O） */
#define PROP_CACHE_CAP 32
typedef struct {
    char key[96];
    char val[92];
    int  vlen;
    int  count;    /* 查询次数（本秒内）*/
    time_t ts;     /* 最近查询时间 */
} prop_cache_t;
static prop_cache_t g_prop_cache[PROP_CACHE_CAP];
static int g_prop_cache_n = 0;

/* 查找缓存项 */
static prop_cache_t *prop_cache_find(const char *name) {
    for (int i = 0; i < g_prop_cache_n; i++)
        if (!__builtin_strcmp(g_prop_cache[i].key, name)) return &g_prop_cache[i];
    return NULL;
}

/* 添加缓存 */
static prop_cache_t *prop_cache_add(const char *name, const char *val, int vlen) {
    if (g_prop_cache_n >= PROP_CACHE_CAP) return NULL;
    prop_cache_t *e = &g_prop_cache[g_prop_cache_n++];
    int kl = (int)__builtin_strlen(name);
    if (kl >= 96) kl = 95;
    __builtin_memcpy(e->key, name, (size_t)kl); e->key[kl] = '\0';
    int vl = vlen < 92 ? vlen : 91;
    __builtin_memcpy(e->val, val, (size_t)vl); e->val[vl] = '\0';
    e->vlen = vl; e->count = 1; e->ts = time(NULL);
    return e;
}

/* 对值末尾字符做微小抖动（不影响可用性）*/
static void prop_jitter(char *val, int vlen) {
    if (vlen <= 0) return;
    int last = vlen - 1;
    /* 大写末位字母: 转小写 */
    if (val[last] >= 'A' && val[last] <= 'Z') { val[last] |= 0x20; return; }
    /* 小写末位字母: 转大写 */
    if (val[last] >= 'a' && val[last] <= 'z') { val[last] &= ~0x20; return; }
    /* 数字末位 0-8: +1; 9 → 0 */
    if (val[last] >= '0' && val[last] <= '9') {
        val[last] = val[last] == '9' ? '0' : val[last]+1; return;
    }
    /* 其他: 不动 */
}

int __system_property_get(const char *name, char *value) {
    JUNK_INSN();   /* [P2] */
    if (!real_prop_get) real_prop_get = (hook_prop_get_t)dlsym(RTLD_NEXT, "__system_property_get");
    if (!HOOKS_READY()) return real_prop_get(name, value);
    /* 白名单属性: 固定返回伪造值 */
    for (const hook_prop_t *e = HOOK_PROPS; e->key; e++) {
        if (__builtin_strcmp(name, e->key) == 0) {
            if (e->value[0]) {
                size_t l = __builtin_strlen(e->value);
                if (value) { __builtin_memcpy(value, e->value, l); value[l] = '\0'; }
                return (int)l;
            }
            if (value) value[0] = '\0';
            return 0;
        }
    }
    /* ro.build.* / ro.product.* 未在白名单 → 返回空 */
    if (name && (strncmp(name,"ro.build.",9)==0 || strncmp(name,"ro.product.",11)==0)) {
        if (value) value[0] = '\0'; return 0;
    }
    /* [P4] 非白名单属性: 缓存 + 频率抖动 */
    prop_cache_t *ce = prop_cache_find(name);
    if (ce) {
        time_t now = time(NULL);
        if (now == ce->ts) ce->count++;
        else { ce->count = 1; ce->ts = now; }
        if (value) {
            __builtin_memcpy(value, ce->val, (size_t)ce->vlen);
            value[ce->vlen] = '\0';
            if (ce->count > 3) prop_jitter(value, ce->vlen); /* 高频抖动 */
        }
        return ce->vlen;
    }
    /* 第一次查询: 获取真实值并缓存 */
    char tmp[92] = {0};
    int real_len = real_prop_get(name, tmp);
    if (real_len > 0 && real_len < 92) {
        prop_cache_add(name, tmp, real_len);
        forge_audit("prop_get", name); /* [P4] 只在首次查询时审计 */
    }
    if (value) { __builtin_memcpy(value, tmp, (size_t)real_len); value[real_len] = '\0'; }
    return real_len;
}

/* ---- JNI_OnLoad ---- */
static void jni_overwrite_build_fields(JNIEnv *env){
    hook_log("[JNI] Build fields overwrite start\n");
    jclass build_cls=(*env)->FindClass(env,"android/os/Build");
    if(!build_cls){hook_log("[JNI] Build class not found\n");return;}
    /* Uses shared BUILD_FIELDS table defined with HOOK_PROPS above */
    for(int i=0;BUILD_FIELDS[i].name;i++){
        jfieldID fid=(*env)->GetStaticFieldID(env,build_cls,BUILD_FIELDS[i].name,BUILD_FIELDS[i].sig);
        if(!fid){(*env)->ExceptionClear(env);continue;}
        jstring s=(*env)->NewStringUTF(env,BUILD_FIELDS[i].val);
        if(s){(*env)->SetStaticObjectField(env,build_cls,fid,s);(*env)->DeleteLocalRef(env,s);}
    }
    (*env)->DeleteLocalRef(env,build_cls);
}

/* ---- JNI_OnLoad — 先转发原版 qimei，再做我们的 hook ---- */
/* 关键: System.loadLibrary("tdmqimei") 只调用我们的 JNI_OnLoad，
 * 原版 qimei 的永远不会执行 → native 方法未注册 → UnsatisfiedLinkError。
 * 必须从 chainloaded so dlsym 原版 JNI_OnLoad 并手动调用。 */
typedef jint (*JNI_OnLoad_t)(JavaVM*,void*);

__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm,void *reserved){
    JUNK_INSN();   /* [P2] */
    JUNK_INSN2();   /* [P2] */
    /* 诊断: 确认 JNI_OnLoad 是否被调用 */
    hook_log("[JNI] JNI_OnLoad called, g_real_qimei_handle=");
    hook_log(g_real_qimei_handle ? "set" : "NULL");
    hook_log("\n");
    /* 1. 转发原版 qimei JNI_OnLoad（注册 native 方法） */
    if (g_real_qimei_handle) {
        JNI_OnLoad_t real_JNI_OnLoad =
            (JNI_OnLoad_t)dlsym(g_real_qimei_handle, "JNI_OnLoad");
        if (real_JNI_OnLoad) {
            hook_log("[JNI] forwarding to real JNI_OnLoad...\n");
            jint real_rc = real_JNI_OnLoad(vm, reserved);
            hook_log("[JNI] real JNI_OnLoad returned\n");
            if (real_rc < JNI_VERSION_1_6) return real_rc;
        } else {
            hook_log("[JNI] WARNING: real JNI_OnLoad not found in chainloaded so\n");
        }
    } else {
        hook_log("[JNI] WARNING: g_real_qimei_handle is NULL, cannot forward\n");
    }
    /* 2. JNI Build 字段覆盖 (安全: 仅 SetStaticObjectField, 无 RegisterNatives).
     * 之前 crash 原因为 deploy.sh --no-hijack bug 导致 hijack 残留冲突,
     * 该 bug 已修复 — Build 字段覆盖现在可以安全使用。 */
    JNIEnv *env=NULL;
    if((*vm)->GetEnv(vm,(void**)&env,JNI_VERSION_1_6)!=JNI_OK)return JNI_VERSION_1_6;
    if(!env)return JNI_VERSION_1_6;
    jni_overwrite_build_fields(env);
    return JNI_VERSION_1_6;
}

__attribute__((destructor))
static void _cleanup(void){ flush_audit(); }
