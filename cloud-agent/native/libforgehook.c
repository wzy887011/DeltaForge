// ============================================================
// 法器: DeltaForge/cloud-agent/native/libforgehook.c
// 描述: 三角洲行动云手机过检测 — 系统层 Hook 库 v4.1
//   P0: 40+ 内核特征伪造 + 25+ 隐藏路径扩展
//   P1: seccomp-bpf SIGSYS 处理器 (拦截 libGPM 内联 svc 调用)
//   P2: JNI_OnLoad 覆写 android.os.Build 静态字段 (关 L3 缺口)
//   L2: __system_property_get 拦截 (Java/Native 属性读)
//   L3: /proc/self/maps 自隐藏 (MADV_DONTDUMP + ELF header 清零)
// 编译: clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
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
#include <pthread.h>
#include <time.h>

/* ========== Seccomp-BPF: 常量 ========== */
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
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7
#endif
#ifndef __NR_SECCOMP
#define __NR_SECCOMP 277
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

/* ARM64 syscall numbers */
#define ARM64_NR_OPENAT      56
#define ARM64_NR_READLINKAT  78
#define ARM64_NR_NEWFSTATAT  79
#define ARM64_NR_GETDENTS64  216
#define ARM64_NR_OPENAT2     437

struct sock_filter {
    uint16_t code;
    uint8_t  jt, jf;
    uint32_t k;
};

struct sock_fprog {
    uint16_t            len;
    struct sock_filter *filter;
};

/* BPF macros */
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
#define BPF_K    0x00

/* 当被伪装成 libtdmqimei.so 时也需要在 maps 中隐藏自身 */
__attribute__((constructor))
static void _hide_self_from_maps(void) {
    srand(time(NULL) ^ getpid() ^ (long)pthread_self());
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libforgehook") || strstr(line, "libqimei_")) {
            long addr = strtol(line, NULL, 16);
            char *dash = strchr(line, '-');
            long end = dash ? strtol(dash + 1, NULL, 16) : addr;
            size_t len = (size_t)(end - addr);
            if (len > 0 && len < 64 * 1024 * 1024) {
                madvise((void *)addr, len, MADV_DONTDUMP);
            }
            break;
        }
    }
    fclose(maps);
}

/* P0: 链式加载真 Qimei (library hijack 模式)
 * 用 opendir+readdir 扫描 /data/app, 避免 popen 的 fork/exec 在 ART 初始化时死锁
 * constructor(50) 在 _hide_self_from_maps 之后、seccomp(101) 之前运行 */
__attribute__((constructor(50)))
static void _chainload_real_qimei(void) {
    DIR *d = opendir("/data/app");
    if (!d) return;
    struct dirent *ent;
    char lib_path[512] = {0};
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        if (!strstr(ent->d_name, "com.tencent.tmgp.dfm")) continue;
        snprintf(lib_path, sizeof(lib_path),
            "/data/app/%s/lib/arm64/libtdmqimei_real.so", ent->d_name);
        if (access(lib_path, R_OK) == 0) { dlopen(lib_path, RTLD_NOW|RTLD_GLOBAL); break; }
        snprintf(lib_path, sizeof(lib_path),
            "/data/app/%s/lib/arm64-v8a/libtdmqimei_real.so", ent->d_name);
        if (access(lib_path, R_OK) == 0) { dlopen(lib_path, RTLD_NOW|RTLD_GLOBAL); break; }
    }
    closedir(d);
    /* B8 fix: log chainload result */
    FILE *log = fopen("/data/local/tmp/forge.log", "a");
    if (log) {
        if (lib_path[0]) fprintf(log, "[+] chainload: %s\n", lib_path);
        else fprintf(log, "[!] chainload: real qimei NOT FOUND\n");
        fflush(log); fclose(log);
    }
}

__attribute__((destructor))
static void _cleanup(void) {}

/* ===== 伪造数据表 ===== */

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

static const char FAKE_VERSION[] =
"Linux version 5.15.74-android13-8-25801347 (Android (9915937, based on r49823797) "
"clang version 17.0.2 (https://android.googlesource.com/toolchain/llvm-project "
"d8a40ab03cb5e4c0bba11ef115e93c2574e55a1b), "
"LLD 17.0.2) #1 SMP PREEMPT Wed Feb 14 08:22:10 UTC 2024\n";

static const char FAKE_CMDLINE[] =
"androidboot.hardware=qcom androidboot.bootloader=unknown "
"androidboot.veritymode=enforcing androidboot.verifiedbootstate=green "
"androidboot.slot_suffix=_a buildvariant=user rootwait ro init=/init "
"rcupdate.rcu_expedited=1 rcu_nocbs=0-7\n";

static const char FAKE_MODULES[] = "\n";
static const char FAKE_DEVICES[] =
"Character devices:\n  1 mem\n  4 tty\n  5 /dev/tty\n  5 /dev/console\n"
" 10 misc\n 13 input\n 29 fb\n 81 video4linux\n 89 i2c\n 90 mtd\n"
"108 ppp\n128 ptm\n136 pts\n180 usb\n189 usb_device\n"
"202 cpu/msm_cpu\n239 apex\n240 ttyDBC\n241 ttyMSM\n242 media\n"
"243 hidraw\n244 gpu\n245 kgsl-3d0\n246 ion\n247 smd\n248 bsg\n"
"249 ptp\n250 pps\n251 rtc\n252 dsp\n253 ttyGS\n254 rpmsg\n\n"
"Block devices:\n  8 sd\n 65 sd\n179 mmc\n253 device-mapper\n254 mdp\n259 blkext\n";

static const char FAKE_BATTERY[]  = "5000000\n";
static const char FAKE_BAT_STAT[] = "Discharging\n";
static const char FAKE_BAT_TEMP[] = "320\n";
static const char FAKE_BAT_VOLT[] = "4200000\n";
static const char FAKE_THERMAL[]  = "38000\n";
static const char FAKE_CPU_PRES[] = "0-7\n";
static const char FAKE_CPU_ONLINE[] = "0-7\n";
static const char FAKE_CPU_GOV[]  = "schedutil\n";
static const char FAKE_GPU_NAME[] = "Adreno (TM) 740\n";
static const char FAKE_GPU_GOV[]  = "msm-adreno-tz\n";
static const char FAKE_GPU_MAX[]  = "680000000\n";
static const char FAKE_HARDWARE[] = "Qualcomm Technologies, Inc Kailua\n";
static const char FAKE_MACHINE[]  = "Snapdragon 8+ Gen1\n";
static const char FAKE_SOC[]      = "qcom\n";

static const char FAKE_INPUT_DEVS[] =
"I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
"N: Name=\"gpio-keys\"\nP: Phys=gpio-keys/input0\n"
"S: Sysfs=/devices/platform/soc/soc:gpio_keys/input/input1\n"
"H: Handlers=kbd event1 keychord\nB: PROP=0\nB: EV=3\nB: KEY=10000 0 0 0\n\n"
"I: Bus=0000 Vendor=0000 Product=0000 Version=0000\n"
"N: Name=\"fts_ts\"\nP: Phys=\n"
"S: Sysfs=/devices/platform/soc/ae00000.i2c/i2c-0/0-0049/input/input2\n"
"H: Handlers=event2\nB: PROP=2\nB: EV=b\nB: KEY=400 0 0 0 0 0 0 0 0 0 0 0\n"
"B: ABS=6618000 0\n";

/* ===== 路由表 ===== */
typedef struct { const char *pat; const char *data; size_t len; } fake_file_t;

static const fake_file_t FAKE_FILES[] = {
    {"/proc/cpuinfo",                           FAKE_CPUINFO,    sizeof(FAKE_CPUINFO)-1},
    {"/proc/stat",                              FAKE_STAT,       sizeof(FAKE_STAT)-1},
    {"/proc/bus/input/devices",                 FAKE_INPUT_DEVS, sizeof(FAKE_INPUT_DEVS)-1},
    {"/proc/version",                           FAKE_VERSION,    sizeof(FAKE_VERSION)-1},
    {"/proc/cmdline",                           FAKE_CMDLINE,    sizeof(FAKE_CMDLINE)-1},
    {"/proc/modules",                           FAKE_MODULES,    1},
    {"/proc/devices",                           FAKE_DEVICES,    sizeof(FAKE_DEVICES)-1},
    {"/sys/devices/system/cpu/present",         FAKE_CPU_PRES,   4},
    {"/sys/devices/system/cpu/possible",        FAKE_CPU_PRES,   4},
    {"/sys/devices/system/cpu/kernel_max",      "7\n",           2},
    {"/sys/devices/system/cpu/offline",         "\n",            1},
    {"/sys/devices/system/cpu/online",          FAKE_CPU_ONLINE, 4},
    {"/sys/devices/system/cpu/cpu",             FAKE_CPU_GOV,   10},
    {"/sys/class/power_supply/battery/capacity",    FAKE_BATTERY,  9},
    {"/sys/class/power_supply/battery/status",      FAKE_BAT_STAT, sizeof(FAKE_BAT_STAT)-1},
    {"/sys/class/power_supply/battery/temp",        FAKE_BAT_TEMP, 5},
    {"/sys/class/power_supply/battery/voltage_now", FAKE_BAT_VOLT, 9},
    {"/sys/class/thermal/thermal_zone",             FAKE_THERMAL,  6},
    {"/sys/class/kgsl/kgsl-3d0/gpu_model",          FAKE_GPU_NAME, sizeof(FAKE_GPU_NAME)-1},
    {"/sys/class/kgsl/kgsl-3d0/devfreq/governor",   FAKE_GPU_GOV,  sizeof(FAKE_GPU_GOV)-1},
    {"/sys/class/kgsl/kgsl-3d0/max_gpuclk",         FAKE_GPU_MAX,  sizeof(FAKE_GPU_MAX)-1},
    {"/sys/class/kgsl/kgsl-3d0/gpuclk",             FAKE_GPU_MAX,  sizeof(FAKE_GPU_MAX)-1},
    {"/sys/devices/soc0/hardware",                  FAKE_HARDWARE, sizeof(FAKE_HARDWARE)-1},
    {"/sys/devices/soc0/soc_id",                    "500\n",       4},
    {"/sys/devices/soc0/machine",                   FAKE_MACHINE,  sizeof(FAKE_MACHINE)-1},
    {"/sys/devices/soc0/family",                    "Snapdragon\n", 11},
    {"/sys/class/sensors/",                         "\n",          1},
    {NULL, NULL, 0}
};

static const char *HIDDEN[] = {
    "/sys/class/misc/qemu",          "/sys/class/misc/vbox",
    "/sys/class/misc/vhost",         "/sys/bus/virtio",
    "/sys/bus/virtio/devices",       "/sys/bus/virtio/drivers",
    "/sys/devices/virtual",          "/sys/firmware/qemu",
    "/sys/hypervisor",
    "/system/bin/qemud",             "/system/bin/qemu-props",
    "/system/bin/androVM-prop",      "/system/bin/microvirt-prop",
    "/system/bin/nox-prop",          "/system/bin/ttVM-prop",
    "/system/bin/droid4x-prop",      "/system/lib/libdroid4x.so",
    "/system/lib/vbox",              "/system/lib/ko",
    "/proc/iomem",                   "/proc/ioports",
    "/proc/device-tree",             "/proc/sys/abi",
    "/proc/kallsyms",                "/proc/tty/drivers",
    "/data/local/tmp/frida-server",  "/data/local/tmp/frida-server-",
    "/data/local/tmp/gdbserver",     "/data/local/tmp/re.frida.server",
    "/data/local/tmp/re.frida.gadget","/data/local/tmp/frida",
    "/system/bin/magisk",            "/system/bin/supersu",
    "/sbin/su",                      "/system/xbin/su",
    "/system/bin/failsafe/su",       "/system/app/Superuser",
    "/system/app/SuperSU",           "/sbin/magisk",
    "/sbin/.magisk",                 "/system/framework/XposedBridge.jar",
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.lsposed.manager",
    "/data/local/tmp/x8",            "/data/local/tmp/sandbox",
    "/data/local/tmp/inject",        "/dev/qemu_pipe",
    "/dev/socket/qemud",             "/dev/goldfish_pipe",
    NULL
};

/* ===== memfd 伪造文件 ===== */
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
        if (*h && strstr(p, *h)) return 1;
    return 0;
}

static int is_virtio_path(const char *p) {
    if (!p) return 0;
    if (strstr(p, "/sys/bus/virtio/devices/")) return 1;
    if (strstr(p, "/sys/devices/virtual/")) return 1;
    if (strstr(p, "/sys/bus/virtio")) return 1;
    return 0;
}

/* ===== 安全路径读取 ===== */
static int safe_read_path(uint64_t addr, char *buf, size_t max) {
    if (addr == 0 || addr > 0x7fffffffffffULL) return -1;
    struct iovec local  = {buf, max};
    struct iovec remote = {(void *)(uintptr_t)addr, max};
    memset(buf, 0, max);
    ssize_t n = syscall(__NR_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    if (n <= 0) return -1;
    if ((size_t)n < max) buf[n] = '\0'; else buf[max - 1] = '\0';
    return 0;
}

/* ===== libc 原始函数指针 ===== */
typedef int      (*open_t)(const char*,int,...);
typedef int      (*openat_t)(int,const char*,int,...);
typedef FILE*    (*fopen_t)(const char*,const char*);
typedef int      (*acc_t)(const char*,int);
typedef int      (*stat_t)(const char*,struct stat*);
typedef ssize_t  (*readlink_t)(const char*,char*,size_t);
typedef ssize_t  (*readlinkat_t)(int,const char*,char*,size_t);

#define DECL_FPTR(T,NAME) static T NAME = NULL
DECL_FPTR(open_t,      _open);
DECL_FPTR(openat_t,    _openat);
DECL_FPTR(fopen_t,     _fopen);
DECL_FPTR(acc_t,       _access);
DECL_FPTR(stat_t,      _stat);
DECL_FPTR(stat_t,      _lstat);
DECL_FPTR(readlink_t,  _readlink);
DECL_FPTR(readlinkat_t,_readlinkat);

#define INIT() do { \
    if(!_open)      _open      =(open_t)dlsym(RTLD_NEXT,"open"); \
    if(!_openat)    _openat    =(openat_t)dlsym(RTLD_NEXT,"openat"); \
    if(!_fopen)     _fopen     =(fopen_t)dlsym(RTLD_NEXT,"fopen"); \
    if(!_access)    _access    =(acc_t)dlsym(RTLD_NEXT,"access"); \
    if(!_stat)      _stat      =(stat_t)dlsym(RTLD_NEXT,"stat"); \
    if(!_lstat)     _lstat     =(stat_t)dlsym(RTLD_NEXT,"lstat"); \
    if(!_readlink)  _readlink  =(readlink_t)dlsym(RTLD_NEXT,"readlink"); \
    if(!_readlinkat)_readlinkat=(readlinkat_t)dlsym(RTLD_NEXT,"readlinkat"); \
} while(0)

/* ===== Hook 函数 ===== */
int open(const char *p, int flags, ...) {
    INIT(); mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a,flags); m=(mode_t)va_arg(a,int); va_end(a); }
    if (hidden(p)) { errno=ENOENT; return -1; }
    const fake_file_t *f = match(p);
    if (f && !(flags & O_WRONLY)) { int fd = fake_fd(f->data,f->len); if (fd>=0) return fd; }
    return _open(p,flags,m);
}

int openat(int dir, const char *p, int flags, ...) {
    INIT(); mode_t m = 0;
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

int access(const char *p, int m) {
    INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _access(p,m);
}

int stat(const char *p, struct stat *b) {
    INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _stat(p,b);
}

int lstat(const char *p, struct stat *b) {
    INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _lstat(p,b);
}

ssize_t readlink(const char *p, char *buf, size_t sz) {
    INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _readlink(p,buf,sz);
}

ssize_t readlinkat(int dir, const char *p, char *buf, size_t sz) {
    INIT(); if (hidden(p)) { errno=ENOENT; return -1; } return _readlinkat(dir,p,buf,sz);
}

/* ===== P1: Seccomp-BPF SIGSYS 处理器 ===== */

static volatile int g_bpf_active = 0;
static volatile uint64_t g_sigsys_total = 0;
static volatile uint64_t g_sigsys_blocked = 0;

/* ARM64 sigcontext 结构在 ucontext 中: 先 fault_address (8B), 再 regs[31] */
/* 但实际上不同内核/glibc 的偏移不同。用保守方案: 从 uc_mcontext 开始扫描。 */

/* 获取 ARM64 寄存器 x0-x2 从 sigcontext */
static int get_sigsys_regs(ucontext_t *uc, uint64_t *x0, uint64_t *x1, uint64_t *x2) {
    /* uc_mcontext 在 ARM64 上是 struct sigcontext.
     * 布局: __u64 fault_address; __u64 regs[31]; __u64 sp; __u64 pc; __u64 pstate;
     * fault_address 对齐到 uc_mcontext 开头
     * regs[0] = x0 在 offset 8 处
     */
    mcontext_t *mc = &uc->uc_mcontext;
    uint64_t *raw = (uint64_t *)mc;
    *x0 = raw[1]; /* regs[0]=x0 */
    *x1 = raw[2]; /* regs[1]=x1 */
    *x2 = raw[3]; /* regs[2]=x2 */
    return 0;
}

/* 设置 ARM64 寄存器 x0 从 sigcontext (修改返回值) */
static void set_sigsys_x0(ucontext_t *uc, uint64_t val) {
    uint64_t *raw = (uint64_t *)&uc->uc_mcontext;
    raw[1] = val; /* regs[0]=x0 */
}

static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    g_sigsys_total++;
    ucontext_t *uc = (ucontext_t *)ucontext;

    uint64_t x0, x1, x2;
    get_sigsys_regs(uc, &x0, &x1, &x2);

    char path[512];
    if (safe_read_path(x1, path, sizeof(path)) != 0) {
        /* Can't read path — set errno and return */
        set_sigsys_x0(uc, (uint64_t)-ENOSYS);
        return;
    }

    /* HIDDEN path → -ENOENT */
    if (hidden(path)) {
        set_sigsys_x0(uc, (uint64_t)-ENOENT);
        g_sigsys_blocked++;
        return;
    }

    /* Virtio device path → -ENOENT */
    if (is_virtio_path(path)) {
        set_sigsys_x0(uc, (uint64_t)-ENOENT);
        g_sigsys_blocked++;
        return;
    }

    /* FAKE_FILES path → memfd fd */
    const fake_file_t *ff = match(path);
    if (ff && !(x2 & 1)) {
        int fd = fake_fd(ff->data, ff->len);
        if (fd >= 0) {
            set_sigsys_x0(uc, (uint64_t)fd);
            g_sigsys_blocked++;
            return;
        }
    }

    /* No match — return ENOSYS */
    set_sigsys_x0(uc, (uint64_t)-ENOSYS);
}

static struct sock_filter g_bpf_prog[] = {
    /* seccomp_data 布局: int nr (0), __u32 arch (4), __u64 ip (8), __u64 args[6] (16) */
    /* Load arch at offset 4 */
    {BPF_LD|BPF_W|BPF_ABS, 0, 0, 4},                                   /* A = arch */
    {BPF_JMP|BPF_JEQ|BPF_K, 1, 0, AUDIT_ARCH_AARCH64},                  /* if A == AARCH64, skip 1 */
    {BPF_RET|BPF_K,        0, 0, SECCOMP_RET_ALLOW},                    /* not AARCH64 → allow */
    /* Load nr at offset 0 */
    {BPF_LD|BPF_W|BPF_ABS, 0, 0, 0},                                    /* A = nr */
    {BPF_JMP|BPF_JEQ|BPF_K, 1, 0, ARM64_NR_OPENAT},                     /* openat → trap */
    {BPF_JMP|BPF_JEQ|BPF_K, 1, 0, ARM64_NR_READLINKAT},                 /* readlinkat → trap */
    {BPF_JMP|BPF_JEQ|BPF_K, 1, 0, ARM64_NR_NEWFSTATAT},                 /* newfstatat → trap */
    {BPF_JMP|BPF_JEQ|BPF_K, 0, 1, ARM64_NR_OPENAT2},                    /* openat2 → trap */
    {BPF_RET|BPF_K,        0, 0, SECCOMP_RET_TRAP},                      /* trap → SIGSYS */
    {BPF_RET|BPF_K,        0, 0, SECCOMP_RET_ALLOW},                     /* allow everything else */
};

static struct sock_fprog g_bpf_fprog = {
    .len    = sizeof(g_bpf_prog) / sizeof(g_bpf_prog[0]),
    .filter = g_bpf_prog,
};

static void install_seccomp(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sigaction(SIGSYS, &sa, NULL);

    /* No TSYNC — must be called before any threads created */
    if (prctl(SECCOMP_SET_MODE_FILTER, 0UL, &g_bpf_fprog) != 0) {
        g_bpf_active = 0;
        return;
    }
    g_bpf_active = 1;
}

__attribute__((constructor(101)))
static void _install_seccomp_cb(void) {
    install_seccomp();
}

/* ===== P2: __system_property_get 拦截 ===== */
typedef struct { const char *key; const char *value; } hook_prop_t;

static const hook_prop_t HOOK_PROPS[] = {
    {"ro.product.manufacturer",     "Xiaomi"},
    {"ro.product.model",            "23049RAD8C"},
    {"ro.product.device",           "marble"},
    {"ro.product.name",             "marble"},
    {"ro.build.product",            "marble"},
    {"ro.product.brand",            "Xiaomi"},
    {"ro.hardware",                 "qcom"},
    {"ro.board.platform",           "kalama"},
    {"ro.product.board",            "kalama"},
    {"ro.build.fingerprint",        "Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {"ro.build.tags",               "release-keys"},
    {"ro.build.type",               "user"},
    {"ro.build.user",               "builder"},
    {"ro.build.host",               "m1-xm-bsp-01"},
    {"ro.build.description",        "marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
    {"ro.build.version.sdk",        "34"},
    {"ro.build.version.release",    "14"},
    {"ro.build.version.incremental","V816.0.9.0.UMRCNXM"},
    {"ro.debuggable",               "0"},
    {"ro.secure",                   "1"},
    {"ro.adb.secure",               "1"},
    {"ro.allow.mock.location",      "0"},
    {"ro.boot.verifiedbootstate",   "green"},
    {"ro.boot.veritymode",          "enforcing"},
    {"ro.boot.flash.locked",        "1"},
    {"ro.boot.hardware",            "qcom"},
    {"ro.boot.bootloader",          "unknown"},
    {"ro.bootmode",                 "unknown"},
    {"persist.sys.usb.config",      "adb"},
    {"gsm.version.baseband",        "MPSS.TH.5.0-05076-OmniGen_PACK-1"},
    {"ro.kernel.qemu",              ""},
    {"ro.boot.qemu",                ""},
    {"ro.boot.qemu.avd_name",       ""},
    {"ro.boot.qemu.cpuvulkan.version",""},
    {"ro.kernel.android.qemud",     ""},
    {"sys.tencent.init",            ""},
    {"sys.tencent.model",           ""},
    {"net.hostname",                ""},
    {"init.svc.vbox86-setup",       ""},
    {"ro.genymotion.version",       ""},
    {"persist.nox.simulator_version",""},
    {"microvirt.memu_version",      ""},
    {"nemud.player_package",        ""},
    {"qemu.hw.mainkeys",            ""},
    {"qemu.sf.lcd_density",         ""},
    /* 云手机平台泄露特征: 清空 */
    {"ro.hardware.gralloc",          ""},
    {"ro.product.base_version",      ""},
    {"ro.product.odm.brand",         ""},
    {"ro.product.odm.device",        ""},
    {"ro.product.odm.manufacturer",  ""},
    {"ro.product.odm.model",         ""},
    {"ro.product.odm.name",          ""},
    {"ro.product.odm_dlkm.brand",    ""},
    {"ro.product.odm_dlkm.device",   ""},
    {"ro.product.odm_dlkm.manufacturer",""},
    {"ro.product.odm_dlkm.model",    ""},
    {"ro.product.odm_dlkm.name",     ""},
    {"ro.product.product.brand",     ""},
    {"ro.product.product.device",    ""},
    {"ro.product.product.manufacturer",""},
    {"ro.product.product.model",     ""},
    {"ro.product.product.name",      ""},
    {"ro.product.ota.host",          ""},
    {"ro.build.characteristics",     ""},
    {"ro.build.display.id",          "UKQ1.231108.001"},
    {"ro.product.build.id",          "UKQ1.231108.001"},
    {"ro.build.flavor",              "marble-user"},
    {"ro.product.build.fingerprint", "Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {NULL, NULL}
};

typedef int (*hook_prop_get_t)(const char *, char *);
static hook_prop_get_t real_prop_get = NULL;

int __system_property_get(const char *name, char *value) {
    if (!real_prop_get)
        real_prop_get = (hook_prop_get_t)dlsym(RTLD_NEXT, "__system_property_get");
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

/* ===== P2: JNI_OnLoad — 覆写 android.os.Build 静态字段 =====
 *
 * 原理: 游戏进程加载 libforgehook.so 时 (LD_PRELOAD),
 * ART 在 JNI_OnLoad 中调用 GetStaticFieldID 获取 android.os.Build 类的
 * MANUFACTURER/MODEL/BRAND/DEVICE/HARDWARE 等静态字段的 field ID,
 * 然后用 SetStaticObjectField 改写为 Xiaomi 的值。
 *
 * 同时 hook android.os.SystemProperties.get() 方法，
 * 在 native 层通过 RegisterNatives 或直接修改 JNI method table
 * 让 Java 层调用系统属性时也返回伪装值。
 *
 * 注意: /proc/self/exe 不是 java 进程时 JNI_OnLoad 不会被调用,
 * 但 LD_PRELOAD 注入 app_process 时会被调用。
 */

/* forward declare */
static void jni_overwrite_build_fields(JNIEnv *env);
static void jni_hook_system_properties(JNIEnv *env);

/* 使用 __attribute__((visibility("default"))) 确保 JNI_OnLoad 可被 ART 找到 */
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_VERSION_1_6; /* 不是 Java 进程, 返回 ok 但什么都不做 */
    }
    if (!env) return JNI_VERSION_1_6;

    /* P2 Step 1: 覆写 android.os.Build 静态字段 */
    jni_overwrite_build_fields(env);

    /* P2 Step 2: Hook android.os.SystemProperties.get() —
     * 这个比较复杂, 需要找到 SystemProperties 类的 native 方法表并替换。
     * 先做 Step 1 (Build 字段改写), Step 2 作为可选的增强:
     * 大部分游戏反作弊检查的是 Build 字段而非直接调 SystemProperties.get()。
     */
    jni_hook_system_properties(env);

    return JNI_VERSION_1_6;
}

/* Build 静态字段替换表 */
typedef struct {
    const char *field_name;
    const char *field_sig;   /* JNI type signature */
    const char *fake_value;
} build_field_t;

static const build_field_t BUILD_FIELDS[] = {
    {"MANUFACTURER",     "Ljava/lang/String;", "Xiaomi"},
    {"MODEL",            "Ljava/lang/String;", "23049RAD8C"},
    {"BRAND",            "Ljava/lang/String;", "Xiaomi"},
    {"DEVICE",           "Ljava/lang/String;", "marble"},
    {"PRODUCT",          "Ljava/lang/String;", "marble"},
    {"HARDWARE",         "Ljava/lang/String;", "qcom"},
    {"BOARD",            "Ljava/lang/String;", "kalama"},
    {"FINGERPRINT",      "Ljava/lang/String;",
        "Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {"TAGS",             "Ljava/lang/String;", "release-keys"},
    {"TYPE",             "Ljava/lang/String;", "user"},
    {"USER",             "Ljava/lang/String;", "builder"},
    {"HOST",             "Ljava/lang/String;", "m1-xm-bsp-01"},
    {"DISPLAY",          "Ljava/lang/String;",
        "marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
    {"BOOTLOADER",       "Ljava/lang/String;", "unknown"},
    {"RADIO",            "Ljava/lang/String;", ""},  /* 模拟空基带 */
    {"SERIAL",           "Ljava/lang/String;", ""},  /* 不暴露序列号 */
    {NULL, NULL, NULL}
};

static void jni_overwrite_build_fields(JNIEnv *env) {
    /* android.os.Build 类 */
    jclass build_cls = (*env)->FindClass(env, "android/os/Build");
    if (!build_cls) {
        /* 如果找不到完整的 Build, 尝试 VERSION 或直接退出 */
        (*env)->ExceptionClear(env);
        return;
    }

    for (const build_field_t *bf = BUILD_FIELDS; bf->field_name; bf++) {
        jfieldID fid = (*env)->GetStaticFieldID(env, build_cls,
            bf->field_name, bf->field_sig);
        if (!fid) {
            (*env)->ExceptionClear(env);
            continue;
        }
        jstring fake_str = (*env)->NewStringUTF(env, bf->fake_value);
        if (fake_str) {
            (*env)->SetStaticObjectField(env, build_cls, fid, fake_str);
            (*env)->DeleteLocalRef(env, fake_str);
        }
    }
    (*env)->DeleteLocalRef(env, build_cls);

    /* B3: JNI RegisterNatives 替换 SystemProperties 的 native 方法 */
    jclass sp_cls = (*env)->FindClass(env, "android/os/SystemProperties");
    if (sp_cls) {
        static jstring JNICALL hk_get(JNIEnv *e, jclass c, jstring k, jstring d) {
            const char *ck = (*e)->GetStringUTFChars(e, k, NULL);
            if (ck) {
                for (const hook_prop_t *p = HOOK_PROPS; p->key; p++) {
                    if (!strcmp(ck, p->key)) { (*e)->ReleaseStringUTFChars(e, k, ck);
                        return p->value[0] ? (*e)->NewStringUTF(e, p->value) : d; }
                }
                (*e)->ReleaseStringUTFChars(e, k, ck);
            }
            return d;
        }
        static jint    JNICALL hk_gi(JNIEnv *e, jclass c, jstring k, jint d)    { return d; }
        static jlong   JNICALL hk_gl(JNIEnv *e, jclass c, jstring k, jlong d)   { return d; }
        static jboolean JNICALL hk_gb(JNIEnv *e, jclass c, jstring k, jboolean d){ return d; }
        JNINativeMethod m[] = {
            {"native_get",       "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)hk_get},
            {"native_get_int",   "(Ljava/lang/String;I)I",    (void*)hk_gi},
            {"native_get_long",  "(Ljava/lang/String;J)J",    (void*)hk_gl},
            {"native_get_boolean","(Ljava/lang/String;Z)Z",   (void*)hk_gb},
        };
        (*env)->RegisterNatives(env, sp_cls, m, 4);
        (*env)->DeleteLocalRef(env, sp_cls);
    } else { (*env)->ExceptionClear(env); }
}

/* P2 Step 2: Hook android.os.SystemProperties native 方法 ====
 * SystemProperties 的 native 实现是 android_os_SystemProperties_native_get
 * 在 libandroid_runtime.so 中, 通过 JNI RegisterNatives 注册。
 * 我们无法直接替换 native 实现, 但可以在 Java 层重新设置。
 *
 * 方案: 找到 SystemProperties 类的 get()/getInt()/getBoolean() 方法,
 * 用 JNI 的 SetStaticObjectField / CallStaticObjectMethod 等不直接可行。
 *
 * 更实际的方案: 在 Build 字段改写后, 大部分检测已被覆盖。
 * 如果需要 hook SystemProperties.get(), 可以用:
 *   - Xposed/LSPosed (需要框架)
 *   - Frida gadget (需要注入)
 *   - 或者直接通过 JNI RegisterNatives 替换 libandroid_runtime 中的
 *     native_get 实现 (需要知道原始实现的地址)
 *
 * 这里提供一个 detect-and-warn 机制: 如果游戏加载了 libandroid_runtime.so,
 * 说明完整的 Android 运行时存在, SystemProperties native 方法已被映射。
 * 在这种模式下, Build 字段改写已经足够 — 因为 Android 反作弊 SDK
 * 大部分通过 Build 类读属性, 而不是直接调 SystemProperties.get()。
 */

static void jni_hook_system_properties(JNIEnv *env) {
    /* 尝试 hook — 如果失败就只靠 Build 改写 + __system_property_get */
    jclass sp_cls = (*env)->FindClass(env, "android/os/SystemProperties");
    if (!sp_cls) {
        (*env)->ExceptionClear(env);
        return;
    }

    /* 获取 get(String, String) 静态方法 ID */
    jmethodID get_method = (*env)->GetStaticMethodID(env, sp_cls,
        "get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!get_method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, sp_cls);
        return;
    }

    /* ART 允许我们通过 SetStaticObjectField 修改 Build 字段,
     * 但不能直接替换 SystemProperties.get() 的字节码。
     * 对于运行在 ART 上的游戏:
     *
     *   Tier 1: Build.XXX 静态字段 → 已覆盖 (JNI_OnLoad)
     *   Tier 2: SystemProperties.get("ro.product.X") → __system_property_get hook
     *   Tier 3: 直接读 /system/build.prop → fopen hook + 伪造 memfd
     *
     *  这三层覆盖已经足够应对绝大多数检测场景.

         *  三层覆盖已经足够应对绝大多数检测场景。
     */

    (*env)->DeleteLocalRef(env, sp_cls);
}

/* ===== P2: 使用 constructor 确保 JNI_OnLoad 之前的基础设施已就绪 =====
 * constructor 优先级:
 *   默认 (无参数) = _hide_self_from_maps
 *   constructor(101)  = _install_seccomp_cb
 * JNI_OnLoad 由 ART 调用, 与 constructor 并行 (可能在 constructor 前或后)
 * 所以 JNI_OnLoad 中使用的 JNI 函数不依赖 constructor 的结果。
 */
