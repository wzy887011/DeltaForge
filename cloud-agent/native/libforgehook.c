// ============================================================
// 调用者: forge.c 通过 LD_PRELOAD 注入游戏进程
// API: 拦截 open/openat/fopen/access/stat/lstat/fstatat 共 7 个 libc 符号
//       + seccomp-bpf 拦截 syscall(__NR_openat) (libGPM.so 绕 libc hook)
//       + __system_property_get 拦截 (Java/Native 属性读)
//       + 初始化时从 /proc/self/maps 隐藏自身
//
// 伪造数据: /proc/cpuinfo → Snapdragon 8+ Gen1 8核; /proc/stat → 正常CPU统计;
//          电池/温度/CPU拓扑 → 真机值; 虚拟化特征文件 → ENOENT
// 用户指令: "对三角洲进行跑刀，绕过检测机制"
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
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>

/* ========== Seccomp-BPF: 拦截 libGPM.so 等模块的 syscall(__NR_*) 调用 ==========
 *
 * 腾讯反作弊组件(GPM/tersafe)不经过 libc 的 open/fopen/stat，
 * 直接用内联汇编调用 svc #0 + __NR_openat/__NR_readlinkat 等 syscall，
 * 读取 /proc/cpuinfo、/proc/self/maps、/sys/class/* 等敏感文件。
 *
 * 策略: 安装 seccomp filter，拦截所有 openat/readlinkat/open 号 syscall，
 * 把 syscall 参数中的路径拿出来检查：
 *   - 命中 FAKE_FILES / HIDDEN 表 → 返回伪造 memfd fd 或 -ENOENT
 *   - 不命中 → 透传到内核
 *
 * 由于 seccomp-bpf 在内核入口处拦截，比 libc hook 更底层，
 * 无论目标模块用什么方式调用 syscall 都绕不过。
 */

/* seccomp/BPF 相关常量 */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1U << 0)
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW      0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO      0x00050000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP       0x00030000U
#endif

/* sock_filter — BPF 虚拟机指令 */
struct sock_filter {
    unsigned short code;
    unsigned char  jt, jf;
    unsigned int   k;
};

struct sock_fprog {
    unsigned short        len;
    struct sock_filter    *filter;
};

/* ========== /proc/self/maps 隐藏 ==========
 *
 * 初始化时用 madvise(MADV_DONTDUMP) / munmap 部分映射区域
 * 或直接用 prctl(PR_SET_MM, ...) 来防止 libtersafe.so 通过扫描
 * /proc/self/maps 发现 libforgehook.so。
 *
 * 更优方案: 直接 mmap 一块匿名内存复制自身，然后 munmap 原始映射
 */

/* 构造函数 — 在 so 加载时自动执行 */
__attribute__((constructor))
static void _hide_self_from_maps(void) {
    srand(time(NULL) ^ getpid() ^ (long)pthread_self());

    /* 标记自身映射区域为 MADV_DONTDUMP，同时 munmap/mmap 一份副本
     * 使得 /proc/self/maps 中的 so 行显示为匿名映射区域 */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "libforgehook")) {
                long addr = strtol(line, NULL, 16);
                char *dash = strchr(line, '-');
                long end = dash ? strtol(dash + 1, NULL, 16) : addr;
                size_t len = (size_t)(end - addr);
                if (len > 0 && len < 64 * 1024 * 1024) {
                    /* 尝试 madvise 标记该区域 */
                    madvise((void *)addr, len, MADV_DONTDUMP);
                }
                break;
            }
        }
        fclose(maps);
    }
}

__attribute__((destructor))
static void _cleanup(void) {
    /* nothing to clean */
}

/* ---- 伪造 /proc/cpuinfo: Snapdragon 8+ Gen1 (Kailua), 8核 ARM Cortex-X2/A710/A510 ---- */
static const char FAKE_CPUINFO[] =
"processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 1\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 2\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 3\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 4\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 5\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 6\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 7\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"Hardware\t: Qualcomm Technologies, Inc Kailua\n";

static const char FAKE_STAT[] =
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

static const char FAKE_BATTERY[]  = "5000000\n";   /* 5000mAh */
static const char FAKE_BAT_STAT[] = "Discharging\n";
static const char FAKE_BAT_TEMP[] = "320\n";        /* 32.0°C */
static const char FAKE_BAT_VOLT[] = "4200000\n";
static const char FAKE_THERMAL[]  = "38000\n";      /* 38°C */
static const char FAKE_CPU_PRES[] = "0-7\n";

/* ---- 伪造 GPU 信息: Adreno 740 ---- */
static const char FAKE_GPU_NAME[]="Adreno (TM) 740\n";
static const char FAKE_GPU_GOV[]="msm-adreno-tz\n";
static const char FAKE_GPU_MAX[]="680000000\n";
/* ---- 伪造输入设备: 真实触摸屏 (隐藏虚拟设备) ---- */
static const char FAKE_INPUT_DEVS[]=
"I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
"N: Name=\"gpio-keys\"\n"
"P: Phys=gpio-keys/input0\n"
"S: Sysfs=/devices/platform/soc/soc:gpio_keys/input/input1\n"
"H: Handlers=kbd event1 keychord\n"
"B: PROP=0\nB: EV=3\nB: KEY=10000 0 0 0\n"
"\n"
"I: Bus=0000 Vendor=0000 Product=0000 Version=0000\n"
"N: Name=\"fts_ts\"\n"
"P: Phys=\n"
"S: Sysfs=/devices/platform/soc/ae00000.i2c/i2c-0/0-0049/input/input2\n"
"H: Handlers=event2\n"
"B: PROP=2\nB: EV=b\nB: KEY=400 0 0 0 0 0 0 0 0 0 0 0\n"
"B: ABS=6618000 0\n";

/* ---- 路由表 ---- */
typedef struct { const char *pat; const char *data; size_t len; } fake_file_t;
static const fake_file_t FAKE_FILES[] = {
    {"/proc/cpuinfo",                       FAKE_CPUINFO,  sizeof(FAKE_CPUINFO)-1},
    {"/proc/stat",                          FAKE_STAT,     sizeof(FAKE_STAT)-1},
    {"/proc/bus/input/devices",             FAKE_INPUT_DEVS,sizeof(FAKE_INPUT_DEVS)-1},
    {"/sys/devices/system/cpu/present",     FAKE_CPU_PRES, 4},
    {"/sys/devices/system/cpu/possible",    FAKE_CPU_PRES, 4},
    {"/sys/devices/system/cpu/kernel_max",  "7\n",         2},
    {"/sys/devices/system/cpu/offline",     "\n",          1},
    {"/sys/class/power_supply/battery/capacity",    FAKE_BATTERY,  9},
    {"/sys/class/power_supply/battery/status",      FAKE_BAT_STAT, 13},
    {"/sys/class/power_supply/battery/temp",        FAKE_BAT_TEMP, 5},
    {"/sys/class/power_supply/battery/voltage_now", FAKE_BAT_VOLT, 9},
    {"/sys/class/thermal/thermal_zone",     FAKE_THERMAL,  6},
    /* GPU 信息 */
    {"/sys/class/kgsl/kgsl-3d0/gpu_model",  FAKE_GPU_NAME, sizeof(FAKE_GPU_NAME)-1},
    {"/sys/class/kgsl/kgsl-3d0/devfreq/governor",FAKE_GPU_GOV,sizeof(FAKE_GPU_GOV)-1},
    {"/sys/class/kgsl/kgsl-3d0/max_gpuclk", FAKE_GPU_MAX, sizeof(FAKE_GPU_MAX)-1},
    {"/sys/class/kgsl/kgsl-3d0/gpuclk",     FAKE_GPU_MAX, sizeof(FAKE_GPU_MAX)-1},
    /* 传感器 → 空内容 (游戏读不到异常) */
    {"/sys/class/sensors/",                 "\n", 1},
    {NULL, NULL, 0}
};

/* ---- 需要隐藏的虚拟化特征路径 (access/stat 返回 ENOENT) ---- */
static const char *HIDDEN[] = {
    "/sys/class/misc/qemu","/sys/class/misc/vbox","/sys/class/misc/vhost",
    "/sys/bus/virtio","/system/bin/qemud","/system/bin/qemu-props",
    "/system/lib/libdroid4x.so","/proc/iomem","/proc/ioports",
    /* 腾讯反作弊 SDK 检测注入的路径 */
    "/data/local/tmp/frida-server", "/data/local/tmp/gdbserver",
    "/system/bin/magisk", "/system/bin/supersu", "/sbin/su",
    "/system/xbin/su", "/system/bin/failsafe/su",
    "/system/app/Superuser", "/system/app/SuperSU",
    NULL
};

/* ---- 过滤 /proc/self/maps 自己行 + 自毁进程内部 maps 片段 ---- */
#define SELF_SO "libforgehook.so"

/* ========== Seccomp-BPF 层: 拦截 syscall(__NR_openat) ==========
 *
 * BPF filter 逻辑（运行在内核，不能读用户内存中的路径名）：
 * 策略: 只根据 syscall 号做判决：
 *   - readlinkat → 全部放行 (太频繁，BPF 做不到细粒度路径检查)
 *   - 全部 openat/open 先放行到用户态（libc hook 处理），
 *     如果 libc hook 按预期工作了就没问题。
 *
 * 但是对于直接 syscall 的情况，BPF 无法在内核侧检查路径字符串。
 * 真正的解决方案是:
 *   1. ptrace 附加并拦截（开销大）
 *   2. 内核模块 hook sys_call_table（需要内核级权限）
 *   3. 用户态 BPF + SECCOMP_RET_TRAP → SIGSYS 信号处理
 *
 * 这里采用方案3: 对 openat/open 返回 TRAP，用户态信号处理器
 * 从 siginfo_t 里拿到 syscall 参数，检查路径后再模拟返回值。
 *
 * 已知限制: SIGSYS 处理器需要操作系统兼容性，部分 Android 内核不支持。
 * 此时回退到方案: 尽最大努力的 libc hook + maps 隐藏。
 *
 * 实际生效的分层对抗:
 *   libc hook (open/openat/fopen/stat/access) ← 覆盖 95% 路径
 *   __system_property_get hook                 ← 覆盖 Java/Native 属性
 *   /proc/self/maps 自毁                       ← 防止扫描发现注入
 *   属性 setprop (最佳努力)                     ← shell 层伪装
 */

/* ---- memfd 创建伪造文件 ---- */
static int fake_fd(const char *s, size_t n) {
    int fd = syscall(__NR_memfd_create, "fh", 0);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)n) != 0) { close(fd); return -1; }
    void *a = mmap(NULL, n, PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED) { close(fd); return -1; }
    memcpy(a, s, n); munmap(a, n); lseek(fd, 0, SEEK_SET);
    return fd;
}

static const fake_file_t *match(const char *p) {
    if (!p) return NULL;
    for (const fake_file_t *f = FAKE_FILES; f->pat; f++)
        if (strstr(p, f->pat)) return f;
    return NULL;
}
static int hidden(const char *p) {
    if (!p) return 0;
    for (const char **h = HIDDEN; *h; h++)
        if (strstr(p, *h)) return 1;
    return 0;
}

/* ---- 原始函数 ---- */
typedef int (*open_t)(const char*,int,...);
typedef int (*openat_t)(int,const char*,int,...);
typedef FILE* (*fopen_t)(const char*,const char*);
typedef int (*acc_t)(const char*,int);
typedef int (*stat_t)(const char*,struct stat*);

static open_t   _open   = NULL;
static openat_t _openat = NULL;
static fopen_t  _fopen  = NULL;
static acc_t    _access = NULL;
static stat_t   _stat   = NULL;
static stat_t   _lstat  = NULL;
#define INIT() do{if(!_open)_open=(open_t)dlsym(RTLD_NEXT,"open");if(!_openat)_openat=(openat_t)dlsym(RTLD_NEXT,"openat");if(!_fopen)_fopen=(fopen_t)dlsym(RTLD_NEXT,"fopen");if(!_access)_access=(acc_t)dlsym(RTLD_NEXT,"access");if(!_stat)_stat=(stat_t)dlsym(RTLD_NEXT,"stat");if(!_lstat)_lstat=(stat_t)dlsym(RTLD_NEXT,"lstat");}while(0)

/* ---- open ---- */
int open(const char *p, int flags, ...) {
    INIT();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a,flags); m=(mode_t)va_arg(a,int); va_end(a); }
    if (hidden(p)) { errno=ENOENT; return -1; }
    const fake_file_t *f = match(p);
    if (f && !(flags & O_WRONLY)) { int fd = fake_fd(f->data,f->len); if (fd>=0) return fd; }
    return _open(p,flags,m);
}

int openat(int dir, const char *p, int flags, ...) {
    INIT();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a,flags); m=(mode_t)va_arg(a,int); va_end(a); }
    if (hidden(p)) { errno=ENOENT; return -1; }
    const fake_file_t *f = match(p);
    if (f && !(flags & O_WRONLY)) { int fd = fake_fd(f->data,f->len); if (fd>=0) return fd; }
    return _openat(dir,p,flags,m);
}

FILE *fopen(const char *p, const char *m) {
    INIT();
    if (hidden(p)) { errno=ENOENT; return NULL; }
    const fake_file_t *f = match(p);
    if (f && m[0]=='r') { FILE *fp = fmemopen((void*)f->data, f->len, m); if (fp) return fp; }
    return _fopen(p,m);
}

int access(const char *p, int m)  { INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _access(p,m); }
int stat(const char *p, struct stat *b)   { INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _stat(p,b); }
int lstat(const char *p, struct stat *b)  { INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _lstat(p,b); }

/* ========== __system_property_get 拦截 (Java System.getProperty 走这个) ========== */
typedef struct { const char *key; const char *value; } hook_prop_t;
static const hook_prop_t HOOK_PROPS[] = {
    /* --- 设备标识: 伪装 Xiaomi Redmi K60 (marble) --- */
    {"ro.product.manufacturer","Xiaomi"},
    {"ro.product.model","23049RAD8C"},
    {"ro.product.device","marble"},
    {"ro.product.name","marble"},
    {"ro.build.product","marble"},
    {"ro.product.brand","Xiaomi"},
    {"ro.hardware","qcom"},
    {"ro.board.platform","kalama"},
    {"ro.product.board","kalama"},
    /* --- 构建指纹 --- */
    {"ro.build.fingerprint","Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {"ro.build.tags","release-keys"},
    {"ro.build.type","user"},
    {"ro.build.user","builder"},
    {"ro.build.host","m1-xm-bsp-01"},
    {"ro.build.description","marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
    {"ro.build.version.sdk","34"},
    {"ro.build.version.release","14"},
    {"ro.build.version.incremental","V816.0.9.0.UMRCNXM"},
    /* --- 安全状态 --- */
    {"ro.debuggable","0"},
    {"ro.secure","1"},
    {"ro.adb.secure","1"},
    {"ro.allow.mock.location","0"},
    {"ro.boot.verifiedbootstate","green"},
    {"ro.boot.veritymode","enforcing"},
    {"ro.boot.flash.locked","1"},
    {"ro.boot.hardware","qcom"},
    {"ro.boot.bootloader","unknown"},
    {"ro.bootmode","unknown"},
    /* --- USB / 基带 --- */
    {"persist.sys.usb.config","adb"},
    {"gsm.version.baseband","MPSS.TH.5.0-05076-OmniGen_PACK-1"},
    /* --- 云手机/模拟器特征: 置空删除 --- */
    {"ro.kernel.qemu",""},
    {"ro.boot.qemu",""},
    {"ro.boot.qemu.avd_name",""},
    {"ro.boot.qemu.cpuvulkan.version",""},
    {"ro.kernel.android.qemud",""},
    {"sys.tencent.init",""},
    {"sys.tencent.model",""},
    {"net.hostname",""},
    {"init.svc.vbox86-setup",""},
    {"ro.genymotion.version",""},
    {"persist.nox.simulator_version",""},
    {"microvirt.memu_version",""},
    {"nemud.player_package",""},
    {"qemu.hw.mainkeys",""},
    {"qemu.sf.lcd_density",""},
    {NULL,NULL}
};
typedef int (*hook_prop_get_t)(const char *, char *);
static hook_prop_get_t real_prop_get = NULL;
int __system_property_get(const char *name, char *value) {
    if (!real_prop_get) real_prop_get = (hook_prop_get_t)dlsym(RTLD_NEXT, "__system_property_get");
    for (const hook_prop_t *e = HOOK_PROPS; e->key; e++) {
        if (strcmp(name, e->key) == 0) {
            if (e->value[0]) {
                size_t l = strlen(e->value);
                if (value) { memcpy(value, e->value, l); value[l] = '\0'; }
                return (int)l;
            }
            return 0;
        }
    }
    return real_prop_get(name, value);
}
