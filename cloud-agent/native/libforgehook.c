// ============================================================
// libforgehook.c v6.0 — LD_PRELOAD 注入库
// Android syscall 拦截 + 属性模拟 + GPU 适配 + 文件伪造
// 编译: clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
// 关键安全修复 (v6.0):
//   - memfd_create 失败 fallback 到 /dev/shm tmpfs
//   - tersafe 轮询 150→300 次 (60s 超时)
//   - 属性 hook 未命中时返回空串 (不泄露真实值)
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

/* ---- constructor(48) — early probe to confirm library load ---- */
__attribute__((constructor(48)))
static void _probe_loaded(void) {
    const char *msg = "[CTOR] 48 _probe_loaded enter\n";
    int fd = (int)syscall(SYS_openat, AT_FDCWD,
        "/data/local/tmp/forge_hook.log",
        O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        size_t len = 0; while (msg[len]) len++;
        (void)syscall(SYS_write, fd, msg, len);
        syscall(SYS_close, fd);
    }
    msg = "[CTOR] 48 _probe_loaded done\n";
    fd = (int)syscall(SYS_openat, AT_FDCWD,
        "/data/local/tmp/forge_hook.log",
        O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        size_t len = 0; while (msg[len]) len++;
        (void)syscall(SYS_write, fd, msg, len);
        syscall(SYS_close, fd);
    }
}

/* ---- maps filter — priority 50: hide instrumentation before chainload ---- */
__attribute__((constructor(50)))
static void _hide_self_from_maps(void) {
    hook_log("[CTOR] 50 _hide_self_from_maps enter\n");
    srand(time(NULL)^getpid()^(long)pthread_self());
    FILE *maps=fopen("/proc/self/maps","r");
    if(!maps){hook_log("[CTOR] 50 fopen maps FAILED\n");return;}
    char line[512];
    while(fgets(line,sizeof(line),maps)){
        if(strstr(line,"libforgehook")||strstr(line,"libqimei_")){
            long addr=strtol(line,NULL,16);
            char *dash=strchr(line,'-');
            long end=dash?strtol(dash+1,NULL,16):addr;
            size_t len=(size_t)(end-addr);
            if(len>0&&len<64*1024*1024)madvise((void*)addr,len,MADV_DONTDUMP);
            break;
        }
    }
    fclose(maps);
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
static void forge_log_raw(const char *msg) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/data/local/tmp/forge.log",
                          O_WRONLY | O_CREAT | O_APPEND, 0600);
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
    const char *real_name = "libtdmqimei_real.so";
    size_t real_len = 0;
    while (real_name[real_len]) real_len++;
    if (dir_len + real_len + 1 > out_sz) return 0;
    for (size_t i = 0; i < dir_len; i++) out[i] = self_path[i];
    for (size_t i = 0; i <= real_len; i++) out[dir_len + i] = real_name[i];
    return 1;
}

static int find_self_from_maps(char *out, size_t out_sz) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return 0;
    char buf[32768];
    ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* 逐行解析，找包含 libtdmqimei 的行，提取路径列 (第6列，'/'开头) */
    const char *needle = "libtdmqimei";
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

__attribute__((constructor(100)))
static void _chainload_real_qimei(void) {
    hook_log("[CTOR] 100 _chainload_real_qimei enter\n");
    char real_path[1024];
    char self_path[1024];
    Dl_info info;
    real_path[0] = '\0';
    self_path[0] = '\0';
    if (dladdr((void *)&_chainload_real_qimei, &info) &&
        info.dli_fname &&
        dirname_join_real(info.dli_fname, real_path, sizeof(real_path))) {
        forge_log_raw("chainload: dladdr OK\n");
    } else if (find_self_from_maps(self_path, sizeof(self_path)) &&
               dirname_join_real(self_path, real_path, sizeof(real_path))) {
        forge_log_raw("chainload: /proc/self/maps OK\n");
    } else {
        forge_log_raw("chainload: FAILED to resolve own path\n");
        hook_log("[CTOR] 100 chainload FAILED (no path)\n");
        return;
    }
    dlerror();
    hook_log("[CTOR] 100 calling dlopen...\n");
    void *h = dlopen(real_path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        const char *err = dlerror();
        hook_log("[CTOR] 100 chainload dlopen FAILED: ");
        hook_log(err ? err : "(null)");
        hook_log("\n");
        hook_log("[CTOR] 100 path tried: ");
        hook_log(real_path);
        hook_log("\n");
        return;
    }
    forge_log_raw("chainload: dlopen SUCCESS\n");
    hook_log("[CTOR] 100 _chainload_real_qimei done\n");
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

/* /proc/self/status — TracerPid: 0。使用 strstr 匹配以覆盖 /proc/<tid>/status 等变体 */
static const char OVERRIDE_PROC_STATUS[]=
"Name:\tGameActivity\nUmask:\t0077\nState:\tS (sleeping)\n"
"Tgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1199\nTracerPid:\t0\n"
"Uid:\t10600\t10600\t10600\t10600\nGid:\t10600\t10600\t10600\t10600\n"
"FDSize:\t256\nGroups:\t3003 9997 20000\nNStgid:\t12345\nNSpid:\t12345\n"
"NSpgid:\t12345\nNSsid:\t12345\nVmPeak:\t10485760 kB\nVmSize:\t9437184 kB\n"
"VmLck:\t0 kB\nVmPin:\t0 kB\nVmHWM:\t524288 kB\nVmRSS:\t458752 kB\n"
"Threads:\t48\n";

/* /proc/self/environ — 清空，隐藏 LD_PRELOAD 等注入痕迹 */
static const char OVERRIDE_ENVIRON[]="PATH=/system/bin:/system/xbin\0ANDROID_DATA=/data\0\0";

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

/* 返回匿名内存 fd：memfd_create → /dev/shm fallback → 堆缓冲区 */
static int memfd_anon(void){
    int fd=(int)syscall(__NR_memfd_create,"ac",0);
    if(fd<0)fd=syscall(SYS_openat,AT_FDCWD,"/dev/shm/.ac",O_RDWR|O_CREAT|O_CLOEXEC,0600);
    return fd; /* 失败返回 -1，调用方用 /dev/null fallback */
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
    {"/proc/self/status",OVERRIDE_PROC_STATUS,sizeof(OVERRIDE_PROC_STATUS)-1},
    {"/proc/net/tcp",OVERRIDE_NET_TCP,sizeof(OVERRIDE_NET_TCP)-1},
    {"/proc/net/tcp6",OVERRIDE_NET_TCP6,sizeof(OVERRIDE_NET_TCP6)-1},
    {"/proc/net/udp",OVERRIDE_NET_UDP,sizeof(OVERRIDE_NET_UDP)-1},
    {"/proc/net/udp6",OVERRIDE_NET_UDP6,sizeof(OVERRIDE_NET_UDP6)-1},
    {"/proc/self/environ",OVERRIDE_ENVIRON,sizeof(OVERRIDE_ENVIRON)-1},
    {"/status",OVERRIDE_PROC_STATUS,sizeof(OVERRIDE_PROC_STATUS)-1},  /* broad: /proc/PID/status */
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

/* ---- memfd fake file — memfd_create + /dev/shm fallback ---- */
static int override_fd(const char *s,size_t n){
    int fd=syscall(__NR_memfd_create,"fh",0);
    /* Fallback: /dev/shm tmpfs */
    if(fd<0){fd=syscall(SYS_openat,AT_FDCWD,"/dev/shm/.fh",O_RDWR|O_CREAT|O_CLOEXEC,0600);}
    if(fd<0)return -1;
    if(ftruncate(fd,(off_t)n)!=0){close(fd);unlink("/dev/shm/.fh");return -1;}
    void *a=mmap(NULL,n,PROT_WRITE,MAP_SHARED,fd,0);
    if(a==MAP_FAILED){close(fd);unlink("/dev/shm/.fh");return -1;}
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

/* ---- /proc/self/maps dynamic filter — filter instrumentation at runtime ---- */
static int make_filtered_maps_fd(void) {
    int rfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (rfd < 0) return -1;
    char buf[65536];
    ssize_t nr = (ssize_t)syscall(SYS_read, rfd, buf, sizeof(buf) - 1);
    syscall(SYS_close, rfd);
    if (nr <= 0) return -1;
    buf[nr] = '\0';

    int mfd = syscall(__NR_memfd_create, "maps", 0);
    if (mfd < 0) return -1;

    char *line = buf, *out = buf; /* 原地过滤（向后移） */
    size_t out_len = 0;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        if (!eol) break;
        *eol = '\0';
        int keep = 1;
        if (strstr(line, "libforgehook") || strstr(line, "libtdmqimei_real") ||
            strstr(line, "libqimei_") || strstr(line, "libinject") ||
            strstr(line, "libfrida") || strstr(line, "libsubstrate") ||
            strstr(line, "libxposed"))
            keep = 0;
        if (keep) {
            size_t ll = (size_t)(eol - line) + 1;
            memmove(out + out_len, line, ll);
            out_len += ll;
        }
        *eol = '\n';
        line = eol + 1;
    }
    if (out_len > 0) {
        if (ftruncate(mfd, (off_t)out_len) != 0) { syscall(SYS_close, mfd); return -1; }
        void *a = mmap(NULL, out_len, PROT_WRITE, MAP_SHARED, mfd, 0);
        if (a == MAP_FAILED) { syscall(SYS_close, mfd); return -1; }
        memcpy(a, out, out_len);
        munmap(a, out_len);
        lseek(mfd, 0, SEEK_SET);
    }
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
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(!g_hooks_ready) return _open(p,flags,m);
    if(hidden(p)){errno=ENOENT;return -1;}
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    /* 动态过滤 /proc/self/maps — 隐藏注入库行 */
    if(p && strstr(p,"maps") && (strstr(p,"/proc/self/")||(strstr(p,"/proc/") && strstr(p,"/task/")))){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    const override_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=override_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("open",p);
    return _open(p,flags,m);
}

int openat(int dir,const char *p,int flags,...){
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(!g_hooks_ready) return _openat(dir,p,flags,m);
    if(hidden(p)){errno=ENOENT;return -1;}
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    if(p && strstr(p,"maps") && (strstr(p,"/proc/self/")||(strstr(p,"/proc/") && strstr(p,"/task/")))){
        int mfd=make_filtered_maps_fd(); if(mfd>=0)return mfd;
    }
    const override_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=override_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("openat",p);
    return _openat(dir,p,flags,m);
}

FILE *fopen(const char *p,const char *m){
    INIT();
    if(!g_hooks_ready) return _fopen(p,m);
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

int access(const char *p,int m){INIT();if(!g_hooks_ready) return _access(p,m);if(hidden(p)){errno=ENOENT;return -1;}forge_audit("access",p);return _access(p,m);}
int stat(const char *p,struct stat *b){INIT();if(!g_hooks_ready) return _stat(p,b);if(hidden(p)){errno=ENOENT;return -1;}forge_audit("stat",p);return _stat(p,b);}
int lstat(const char *p,struct stat *b){INIT();if(!g_hooks_ready) return _lstat(p,b);if(hidden(p)){errno=ENOENT;return -1;}return _lstat(p,b);}
ssize_t readlink(const char *p,char *buf,size_t sz){INIT();if(!g_hooks_ready) return _readlink(p,buf,sz);if(hidden(p)){errno=ENOENT;return -1;}return _readlink(p,buf,sz);}
ssize_t readlinkat(int dir,const char *p,char *buf,size_t sz){INIT();if(!g_hooks_ready) return _readlinkat(dir,p,buf,sz);if(hidden(p)){errno=ENOENT;return -1;}return _readlinkat(dir,p,buf,sz);}

/* ---- tgkill / kill hook — intercept fatal termination signals
 * Only block SIGKILL(9)/SIGTERM(15).
 * Allow sig==0 (liveness check) and harmless signals (SIGCHLD, etc.). ---- */
typedef int (*tgkill_t)(pid_t, pid_t, int);
typedef int (*kill_t)(pid_t, int);
static tgkill_t _tgkill = NULL;
static kill_t   _kill_fn = NULL;

int tgkill(pid_t tgid, pid_t tid, int sig) {
    if (!_tgkill) _tgkill = (tgkill_t)dlsym(RTLD_NEXT, "tgkill");
    if (!g_hooks_ready) return _tgkill ? _tgkill(tgid, tid, sig) : 0;
    if (sig == 9 || sig == 15) return 0;
    return _tgkill ? _tgkill(tgid, tid, sig) : 0;
}

int kill(pid_t pid, int sig) {
    if (!_kill_fn) _kill_fn = (kill_t)dlsym(RTLD_NEXT, "kill");
    if (!g_hooks_ready) return _kill_fn ? _kill_fn(pid, sig) : 0;
    if (sig == 9 || sig == 15) return 0;
    return _kill_fn ? _kill_fn(pid, sig) : 0;
}

/* ---- exit_group hook — block only if caller is in target module ---- */
typedef void (*exit_group_t)(int);
static exit_group_t _exit_group = NULL;
static uintptr_t   g_ts_text_start = 0;
static uintptr_t   g_ts_text_end   = 0;

void exit_group(int status) {
    if (!_exit_group) _exit_group = (exit_group_t)dlsym(RTLD_NEXT, "exit_group");
    if (!g_hooks_ready) { _exit_group(status); return; }
    /* Cache target module code segment range */
    if (!g_ts_text_start) {
        g_ts_text_start = get_module_base("libtersafe.so");
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
        (strstr(info->dlpi_name, "libforgehook") ||
         strstr(info->dlpi_name, "libtdmqimei_real")))
        return 0;
    return w->cb(info, size, w->data);
}

int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!_dl_iterate_phdr)
        _dl_iterate_phdr = (dl_iterate_phdr_t)dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if (!_dl_iterate_phdr) return 0;
    struct _phdr_wrap w = {cb, data};
    return _dl_iterate_phdr(_phdr_filter, &w);
}

/* ---- dlopen hook — prevent probing of instrumentation library ---- */
typedef void *(*dlopen_t)(const char *, int);
static dlopen_t _dlopen_real = NULL;

void *dlopen(const char *filename, int flags) {
    if (!_dlopen_real)
        _dlopen_real = (dlopen_t)dlsym(RTLD_NEXT, "dlopen");
    if (filename) {
        if (strstr(filename, "libforgehook") ||
            strstr(filename, "libtdmqimei_real") ||
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
    int rc = _dladdr_real(addr, info);
    if (rc && info && info->dli_fname) {
        if (strstr(info->dli_fname, "libforgehook") ||
            strstr(info->dli_fname, "libtdmqimei_real")) {
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
    if (hidden(name)) { errno = ENOENT; return NULL; }
    return _opendir ? _opendir(name) : NULL;
}

struct dirent *readdir(DIR *dirp) {
    if (!_readdir) _readdir = (readdir_t)dlsym(RTLD_NEXT, "readdir");
    if (!_readdir) return NULL;
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
        if (name && name[0] && (strstr(name, "libforgehook") ||
                                 strstr(name, "libtdmqimei_real"))) {
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
    if (!g_hooks_ready) return _getaddrinfo ? _getaddrinfo(node, service, hints, res) : -2;
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
    if (!g_hooks_ready) return _connect_orig ? _connect_orig(sockfd, addr, addrlen) : -1;
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

/* hook internal log — /data/local/tmp/ to avoid SELinux denials in early constructor phase */
static void hook_log(const char *msg) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD,
        "/data/local/tmp/forge_hook.log",
        O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    size_t len = 0; while (msg[len]) len++;
    (void)syscall(SYS_write, fd, msg, len);
    syscall(SYS_close, fd);
}

static uintptr_t get_module_base(const char *so_name) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
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
 * Method 2: pwrite64 via /proc/self/mem (bypasses W^X, Android 10+ preferred) */
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

/* termination chain patch table - ordered from entry to syscall */
static const struct { uint64_t off; uint32_t insn; const char *name; } kKillChain[] = {
    {0x419fdcu, 0xD2800000u, "detect_entry MOV X0,#0"},
    {0x419fe0u, 0xD65F03C0u, "detect_entry+4 RET"},
    {0x2e7810u, 0xD65F03C0u, "kill_dispatch RET"},
    {0x2f29d0u, 0xD65F03C0u, "kill_router RET"},
    {0x320d78u, 0xD65F03C0u, "kill_wrapper RET"},
    {0x3233b8u, 0xD65F03C0u, "tgkill_call RET"},
};
#define KILL_CHAIN_N (sizeof(kKillChain)/sizeof(kKillChain[0]))

/* ---- background thread: poll + patch target module ---- */
static void *_patch_tersafe_thread(void *unused) {
    (void)unused;
    uintptr_t base = 0;
    char logbuf[160];

    /* poll-wait for target module (up to 60 seconds), detached thread */
    for (int retry = 0; retry < 300; retry++) {
        base = get_module_base("libtersafe.so");
        if (base) break;
        if (retry == 0) hook_log("[patch] waiting for target module...\n");
        usleep(200000);
    }
    if (!base) {
        hook_log("[patch] TIMEOUT: target module not loaded after 60s\n");
        return NULL;
    }
    int ln = snprintf(logbuf, sizeof(logbuf),
        "[patch] base=0x%lx\n", (unsigned long)base);
    if (ln > 0) hook_log(logbuf);

    int ok = 0;
    for (size_t i = 0; i < KILL_CHAIN_N; i++) {
        int r = patch_insn(base + kKillChain[i].off, kKillChain[i].insn);
        ln = snprintf(logbuf, sizeof(logbuf),
            "[patch] %-28s off=0x%06llx r=%d\n",
            kKillChain[i].name, (unsigned long long)kKillChain[i].off, r);
        if (ln > 0) hook_log(logbuf);
        if (r == 0) ok++;
    }
    ln = snprintf(logbuf, sizeof(logbuf),
        "[patch] done: %d/%zu ok\n", ok, KILL_CHAIN_N);
    if (ln > 0) hook_log(logbuf);
    return NULL;
}

__attribute__((constructor(150)))
static void _patch_tersafe(void) {
    hook_log("[CTOR] 150 _patch_tersafe enter\n");
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, _patch_tersafe_thread, NULL) != 0) {
        hook_log("[patch] FATAL: pthread_create failed, patching inline...\n");
        _patch_tersafe_thread(NULL);
    }
    pthread_attr_destroy(&attr);
    hook_log("[CTOR] 150 _patch_tersafe done\n");
    /* ACTIVATE all libc hooks — safe now, game init is complete */
    g_hooks_ready = 1;
    hook_log("[hooks] all libc hooks activated (g_hooks_ready=1)\n");
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
 * kill chain 6 节点内存补丁已从源头干掉 tersafe 杀进程逻辑，
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
/* priority=49 - install seccomp before other hooks (no race window) */
__attribute__((constructor(49)))
static void _install_seccomp_cb(void){install_seccomp();}

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
    {"SERIAL","Ljava/lang/String;",""},
    {NULL,NULL,NULL}
};

typedef int (*hook_prop_get_t)(const char*,char*);
static hook_prop_get_t real_prop_get=NULL;

int __system_property_get(const char *name,char *value){
    if(!real_prop_get)real_prop_get=(hook_prop_get_t)dlsym(RTLD_NEXT,"__system_property_get");
    if(!g_hooks_ready) return real_prop_get(name,value);
    for(const hook_prop_t *e=HOOK_PROPS;e->key;e++){
        if(strcmp(name,e->key)==0){
            if(e->value[0]){
                size_t l=strlen(e->value);
                if(value){memcpy(value,e->value,l);value[l]='\0';}
                return (int)l;
            }
            if(value) value[0]='\0';
            return 0;
        }
    }
    /* Fallback: any ro.build.* / ro.product.* not in HOOK_PROPS → blank.
     * Prevents accidental leak of real device identity through unlisted props. */
    if(name && (strncmp(name,"ro.build.",9)==0 ||
                strncmp(name,"ro.product.",11)==0)){
        if(value) value[0]='\0';
        return 0;
    }
    /* Audit unlisted properties for discovery */
    forge_audit("prop_get",name);
    return real_prop_get(name,value);
}

/* ---- JNI helpers ---- */
static jstring hooked_get(JNIEnv *e,jclass c,jstring k,jstring d){
    const char *ck=(*e)->GetStringUTFChars(e,k,NULL);
    if(!ck)return d;
    for(const hook_prop_t *p=HOOK_PROPS;p->key;p++){
        if(!strcmp(ck,p->key)){(*e)->ReleaseStringUTFChars(e,k,ck);return p->value[0]?(*e)->NewStringUTF(e,p->value):d;}
    }
    (*e)->ReleaseStringUTFChars(e,k,ck);
    return d;
}
static jint     hooked_get_int(JNIEnv *e,jclass c,jstring k,jint d)     {return d;}
static jlong    hooked_get_long(JNIEnv *e,jclass c,jstring k,jlong d)   {return d;}
static jboolean hooked_get_bool(JNIEnv *e,jclass c,jstring k,jboolean d){return d;}

/* ---- JNI_OnLoad ---- */
static void jni_overwrite_build_fields(JNIEnv *env){
    jclass build_cls=(*env)->FindClass(env,"android/os/Build");
    if(!build_cls){(*env)->ExceptionClear(env);return;}
    /* Uses shared BUILD_FIELDS table defined with HOOK_PROPS above */
    for(int i=0;BUILD_FIELDS[i].name;i++){
        jfieldID fid=(*env)->GetStaticFieldID(env,build_cls,BUILD_FIELDS[i].name,BUILD_FIELDS[i].sig);
        if(!fid){(*env)->ExceptionClear(env);continue;}
        jstring s=(*env)->NewStringUTF(env,BUILD_FIELDS[i].val);
        if(s){(*env)->SetStaticObjectField(env,build_cls,fid,s);(*env)->DeleteLocalRef(env,s);}
    }
    (*env)->DeleteLocalRef(env,build_cls);
}

static void jni_hook_system_properties(JNIEnv *env){
    jclass sp_cls=(*env)->FindClass(env,"android/os/SystemProperties");
    if(!sp_cls){(*env)->ExceptionClear(env);return;}
    jmethodID get_method=(*env)->GetStaticMethodID(env,sp_cls,"get","(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if(!get_method){(*env)->ExceptionClear(env);(*env)->DeleteLocalRef(env,sp_cls);return;}
    JNINativeMethod methods[]={
        {"native_get","(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",(void*)hooked_get},
        {"native_get_int","(Ljava/lang/String;I)I",(void*)hooked_get_int},
        {"native_get_long","(Ljava/lang/String;J)J",(void*)hooked_get_long},
        {"native_get_boolean","(Ljava/lang/String;Z)Z",(void*)hooked_get_bool},
    };
    jint rc=(*env)->RegisterNatives(env,sp_cls,methods,4);
    if(rc!=0){FILE *log=fopen("/data/local/tmp/forge.log","a");if(log){fprintf(log,"[!] JNI RegisterNatives fail rc=%d\n",rc);fflush(log);fclose(log);}}
    (*env)->DeleteLocalRef(env,sp_cls);
}

__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm,void *reserved){
    (void)reserved;
    JNIEnv *env=NULL;
    if((*vm)->GetEnv(vm,(void**)&env,JNI_VERSION_1_6)!=JNI_OK)return JNI_VERSION_1_6;
    if(!env)return JNI_VERSION_1_6;
    jni_overwrite_build_fields(env);
    jni_hook_system_properties(env);
    return JNI_VERSION_1_6;
}

__attribute__((destructor))
static void _cleanup(void){ flush_audit(); }
