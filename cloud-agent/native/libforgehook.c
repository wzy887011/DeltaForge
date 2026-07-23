// ============================================================
// DeltaForge/cloud-agent/native/libforgehook.c v5.6
// Shared library — hook __system_property_get, fopen/open, seccomp-bpf, JNI
//                  getenv(LD_PRELOAD), dl_iterate_phdr, opendir/readdir
// Compile: clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
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
#define ARM64_NR_READLINKAT  78
#define ARM64_NR_NEWFSTATAT  79
#define ARM64_NR_KILL        129  /* kill — 整进程杀 */
#define ARM64_NR_TKILL       130  /* tkill — 单线程杀 (tgkill 前身) */
#define ARM64_NR_TGKILL      131  /* tgkill — TerSafe 直接 SVC 发送自杀信号 */
#define ARM64_NR_GETDENTS64  216
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

/* ---- maps hide — priority 50: 在 chainload 之前先隐藏自身 ---- */
__attribute__((constructor(50)))
static void _hide_self_from_maps(void) {
    srand(time(NULL)^getpid()^(long)pthread_self());
    FILE *maps=fopen("/proc/self/maps","r");
    if(!maps)return;
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
}

/* ---- forge audit log — buffered writes to avoid per-call disk I/O ---- */
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


/* ---- chainload real Qimei ---- */
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
        return;
    }
    dlerror();
    void *h = dlopen(real_path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        forge_log_raw("chainload: dlopen FAILED: ");
        forge_log_raw(dlerror());
        forge_log_raw("\n");
        return;
    }
    forge_log_raw("chainload: dlopen SUCCESS\n");
}

/* ---- fake data tables ---- */
static const char FAKE_CPUINFO[]=
"processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 1\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 2\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 3\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 4\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 5\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 6\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"processor\t: 7\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x51\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0x001\nCPU revision\t: 0\n\n"
"Hardware\t: Qualcomm Technologies, Inc Kailua\n";

static const char FAKE_STAT[]=
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

static const char FAKE_VERSION[]=
"Linux version 5.15.74-android13-8-25801347 (Android (9915937, based on r49823797) "
"clang version 17.0.2 (https://android.googlesource.com/toolchain/llvm-project "
"d8a40ab03cb5e4c0bba11ef115e93c2574e55a1b), "
"LLD 17.0.2) #1 SMP PREEMPT Wed Feb 14 08:22:10 UTC 2024\n";

static const char FAKE_CMDLINE[]=
"androidboot.hardware=qcom androidboot.bootloader=unknown "
"androidboot.veritymode=enforcing androidboot.verifiedbootstate=green "
"androidboot.slot_suffix=_a buildvariant=user rootwait ro init=/init "
"rcupdate.rcu_expedited=1 rcu_nocbs=0-7\n";

static const char FAKE_MODULES[]="\n";
static const char FAKE_DEVICES[]=
"Character devices:\n  1 mem\n  4 tty\n  5 /dev/tty\n  5 /dev/console\n"
" 10 misc\n 13 input\n 29 fb\n 81 video4linux\n 89 i2c\n 90 mtd\n"
"108 ppp\n128 ptm\n136 pts\n180 usb\n189 usb_device\n"
"202 cpu/msm_cpu\n239 apex\n240 ttyDBC\n241 ttyMSM\n242 media\n"
"243 hidraw\n244 gpu\n245 kgsl-3d0\n246 ion\n247 smd\n248 bsg\n"
"249 ptp\n250 pps\n251 rtc\n252 dsp\n253 ttyGS\n254 rpmsg\n\n"
"Block devices:\n  8 sd\n 65 sd\n179 mmc\n253 device-mapper\n254 mdp\n259 blkext\n";

static const char FAKE_BATTERY[]="5000000\n";
static const char FAKE_BAT_STAT[]="Discharging\n";
static const char FAKE_BAT_TEMP[]="320\n";
static const char FAKE_BAT_VOLT[]="4200000\n";
static const char FAKE_THERMAL[]="38000\n";
static const char FAKE_CPU_PRES[]="0-7\n";
static const char FAKE_CPU_ONLINE[]="0-7\n";
static const char FAKE_CPU_GOV[]="schedutil\n";
static const char FAKE_GPU_NAME[]="Adreno (TM) 740\n";
static const char FAKE_GPU_GOV[]="msm-adreno-tz\n";
static const char FAKE_GPU_MAX[]="680000000\n";
static const char FAKE_HARDWARE[]="Qualcomm Technologies, Inc Kailua\n";
static const char FAKE_MACHINE[]="Snapdragon 8+ Gen1\n";

/* /proc/self/status — TracerPid: 0 防止反调试检测 ptrace */
static const char FAKE_PROC_STATUS[]=
"Name:\tGameActivity\nUmask:\t0077\nState:\tS (sleeping)\n"
"Tgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1199\nTracerPid:\t0\n"
"Uid:\t10600\t10600\t10600\t10600\nGid:\t10600\t10600\t10600\t10600\n"
"FDSize:\t256\nGroups:\t3003 9997 20000\nNStgid:\t12345\nNSpid:\t12345\n"
"NSpgid:\t12345\nNSsid:\t12345\nVmPeak:\t10485760 kB\nVmSize:\t9437184 kB\n"
"VmLck:\t0 kB\nVmPin:\t0 kB\nVmHWM:\t524288 kB\nVmRSS:\t458752 kB\n"
"Threads:\t48\n";

/* /proc/net/tcp — 空响应，不暴露调试端口 */
static const char FAKE_NET_TCP[]=
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";

static const char FAKE_NET_TCP6[]=
"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";

static const char FAKE_INPUT_DEVS[]=
"I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
"N: Name=\"gpio-keys\"\nP: Phys=gpio-keys/input0\n"
"S: Sysfs=/devices/platform/soc/soc:gpio_keys/input/input1\n"
"H: Handlers=kbd event1 keychord\nB: PROP=0\nB: EV=3\nB: KEY=10000 0 0 0\n\n"
"I: Bus=0000 Vendor=0000 Product=0000 Version=0000\n"
"N: Name=\"fts_ts\"\nP: Phys=\n"
"S: Sysfs=/devices/platform/soc/ae00000.i2c/i2c-0/0-0049/input/input2\n"
"H: Handlers=event2\nB: PROP=2\nB: EV=b\nB: KEY=400 0 0 0 0 0 0 0 0 0 0 0\n"
"B: ABS=6618000 0\n";

/* ---- null redirect list — 只重定向纯上报文件，不碰游戏配置/SDK状态文件 ---- */
static const char *NULL_REDIRECT[]={
    "crashSight_db_",      /* CrashSight 崩溃数据库 — 纯上报 */
    "ace_shell_db.dat",    /* ACE shell 数据库 — 纯检测数据 */
    "ace_cache_db.dat",    /* ACE 缓存数据库 */
    "tersafe.update",      /* TerSafe 更新包 */
    "tdm_track.dat",       /* TDM 追踪数据 */
    "sys_log_",            /* CrashSight 系统日志 */
    "jni_log_",            /* CrashSight JNI 日志 */
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

/* 返回匿名内存 fd：读写均在内存中，不落盘 */
static int memfd_anon(void){
    int fd=(int)syscall(__NR_memfd_create,"ac",0);
    return fd; /* 失败返回 -1，调用方 fallback 到 /dev/null */
}

/* ---- file routing table ---- */
typedef struct {const char *pat;const char *data;size_t len;}fake_file_t;
static const fake_file_t FAKE_FILES[]={
    {"/proc/cpuinfo",FAKE_CPUINFO,sizeof(FAKE_CPUINFO)-1},
    {"/proc/stat",FAKE_STAT,sizeof(FAKE_STAT)-1},
    {"/proc/bus/input/devices",FAKE_INPUT_DEVS,sizeof(FAKE_INPUT_DEVS)-1},
    {"/proc/version",FAKE_VERSION,sizeof(FAKE_VERSION)-1},
    {"/proc/cmdline",FAKE_CMDLINE,sizeof(FAKE_CMDLINE)-1},
    {"/proc/modules",FAKE_MODULES,1},
    {"/proc/devices",FAKE_DEVICES,sizeof(FAKE_DEVICES)-1},
    {"/sys/devices/system/cpu/present",FAKE_CPU_PRES,4},
    {"/sys/devices/system/cpu/possible",FAKE_CPU_PRES,4},
    {"/sys/devices/system/cpu/kernel_max","7\n",2},
    {"/sys/devices/system/cpu/offline","\n",1},
    {"/sys/devices/system/cpu/online",FAKE_CPU_ONLINE,4},
    {"/sys/devices/system/cpu/cpu",FAKE_CPU_GOV,10},
    {"/sys/class/power_supply/battery/capacity",FAKE_BATTERY,9},
    {"/sys/class/power_supply/battery/status",FAKE_BAT_STAT,sizeof(FAKE_BAT_STAT)-1},
    {"/sys/class/power_supply/battery/temp",FAKE_BAT_TEMP,5},
    {"/sys/class/power_supply/battery/voltage_now",FAKE_BAT_VOLT,9},
    {"/sys/class/thermal/thermal_zone",FAKE_THERMAL,6},
    {"/sys/class/kgsl/kgsl-3d0/gpu_model",FAKE_GPU_NAME,sizeof(FAKE_GPU_NAME)-1},
    {"/sys/class/kgsl/kgsl-3d0/devfreq/governor",FAKE_GPU_GOV,sizeof(FAKE_GPU_GOV)-1},
    {"/sys/class/kgsl/kgsl-3d0/max_gpuclk",FAKE_GPU_MAX,sizeof(FAKE_GPU_MAX)-1},
    {"/sys/class/kgsl/kgsl-3d0/gpuclk",FAKE_GPU_MAX,sizeof(FAKE_GPU_MAX)-1},
    {"/sys/devices/soc0/hardware",FAKE_HARDWARE,sizeof(FAKE_HARDWARE)-1},
    {"/sys/devices/soc0/soc_id","500\n",4},
    {"/sys/devices/soc0/machine",FAKE_MACHINE,sizeof(FAKE_MACHINE)-1},
    {"/sys/devices/soc0/family","Snapdragon\n",11},
    {"/sys/class/sensors/","\n",1},
    {"/proc/self/status",FAKE_PROC_STATUS,sizeof(FAKE_PROC_STATUS)-1},
    {"/proc/net/tcp",FAKE_NET_TCP,sizeof(FAKE_NET_TCP)-1},
    {"/proc/net/tcp6",FAKE_NET_TCP6,sizeof(FAKE_NET_TCP6)-1},
    {NULL,NULL,0}
};

static const char *HIDDEN[]={
    "/sys/class/misc/qemu","/sys/class/misc/vbox",
    "/sys/class/misc/vhost","/sys/bus/virtio",
    "/sys/bus/virtio/devices","/sys/bus/virtio/drivers",
    "/sys/devices/virtual","/sys/firmware/qemu",
    "/sys/hypervisor",
    "/dev/tee0","/dev/tee1","/dev/teepriv0",  /* 云手机虚拟 TEE */
    "/dev/qemu_pipe","/dev/socket/qemud","/dev/goldfish_pipe",
    "/system/bin/qemud","/system/bin/qemu-props",
    "/system/bin/androVM-prop","/system/bin/microvirt-prop",
    "/system/bin/nox-prop","/system/bin/ttVM-prop",
    "/system/bin/droid4x-prop","/system/lib/libdroid4x.so",
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

/* ---- memfd fake file ---- */
static int fake_fd(const char *s,size_t n){
    int fd=syscall(__NR_memfd_create,"fh",0);
    if(fd<0)return -1;
    if(ftruncate(fd,(off_t)n)!=0){close(fd);return -1;}
    void *a=mmap(NULL,n,PROT_WRITE,MAP_SHARED,fd,0);
    if(a==MAP_FAILED){close(fd);return -1;}
    memcpy(a,s,n);munmap(a,n);lseek(fd,0,SEEK_SET);
    return fd;
}

static const fake_file_t *match(const char *p){
    if(!p)return NULL;
    for(const fake_file_t *f=FAKE_FILES;f->pat;f++)
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
    if(hidden(p)){errno=ENOENT;return -1;}
    /* 反作弊数据文件重定向到匿名内存 — 写入不落盘 */
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    const fake_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=fake_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("open",p);
    return _open(p,flags,m);
}

int openat(int dir,const char *p,int flags,...){
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(hidden(p)){errno=ENOENT;return -1;}
    if(null_redir(p)){int mfd=memfd_anon();if(mfd>=0)return mfd;return _open("/dev/null",O_RDWR,0);}
    const fake_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=fake_fd(f->data,f->len);if(fd>=0)return fd;}
    if(!f&&!hidden(p)) forge_audit("openat",p);
    return _openat(dir,p,flags,m);
}

FILE *fopen(const char *p,const char *m){
    INIT();
    if(hidden(p)){errno=ENOENT;return NULL;}
    if(null_redir(p)){
        /* 写入模式 → /dev/null；读取模式 → 空内存 */
        if(m[0]=='w'||m[0]=='a') return _fopen("/dev/null",m);
        static char nb[64]={0}; FILE *fp=fmemopen(nb,sizeof(nb),"r"); if(fp) return fp;
    }
    const fake_file_t *f=match(p);
    if(f&&m[0]=='r'){FILE *fp=fmemopen((void*)f->data,f->len,m);if(fp)return fp;}
    if(!f&&!hidden(p)) forge_audit("fopen",p);
    return _fopen(p,m);
}

int access(const char *p,int m){INIT();if(hidden(p)){errno=ENOENT;return -1;}forge_audit("access",p);return _access(p,m);}
int stat(const char *p,struct stat *b){INIT();if(hidden(p)){errno=ENOENT;return -1;}forge_audit("stat",p);return _stat(p,b);}
int lstat(const char *p,struct stat *b){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _lstat(p,b);}
ssize_t readlink(const char *p,char *buf,size_t sz){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _readlink(p,buf,sz);}
ssize_t readlinkat(int dir,const char *p,char *buf,size_t sz){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _readlinkat(dir,p,buf,sz);}

/* ---- tgkill / kill hook — 拦截 TerSafe 自杀信号
 * 拦截所有发向自身的 fatal 信号(1-31)，sig==0 放行(pthread 存活检查) ---- */
typedef int (*tgkill_t)(pid_t, pid_t, int);
typedef int (*kill_t)(pid_t, int);
static tgkill_t _tgkill = NULL;
static kill_t   _kill_fn = NULL;

int tgkill(pid_t tgid, pid_t tid, int sig) {
    if (!_tgkill) _tgkill = (tgkill_t)dlsym(RTLD_NEXT, "tgkill");
    /* sig==0 是 pthread_kill 的线程存活检查，放行 */
    if (sig > 0 && sig <= 31) return 0;
    return _tgkill ? _tgkill(tgid, tid, sig) : 0;
}

int kill(pid_t pid, int sig) {
    if (!_kill_fn) _kill_fn = (kill_t)dlsym(RTLD_NEXT, "kill");
    /* 拦截所有发向自身的 fatal 信号 */
    if (sig > 0 && sig <= 31) return 0;
    return _kill_fn ? _kill_fn(pid, sig) : 0;
}

/* ---- P0ext: getenv — 拦截 LD_PRELOAD / LD_LIBRARY_PATH 检测 ---- */
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

/* ---- P0ext: dl_iterate_phdr — 过滤 libforgehook 被枚举 ---- */
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

/* ---- P0ext: opendir / readdir — 目录级隐藏 ---- */
typedef DIR  *(*opendir_t)(const char *);
typedef struct dirent *(*readdir_t)(DIR *);
static opendir_t _opendir = NULL;
static readdir_t _readdir = NULL;

static const char *FILT_NAMES[] = {
    "frida", "gdbserver", "gdb", "magisk", ".magisk", "supersu",
    "xposed", "lsposed", "edxposed", "substrate",
    "qemu", "vbox", "vhost", "goldfish", "libdroid4x",
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

/* readdir64 — TerSafe 可能走64位版枚举 /proc，同样过滤 */
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

/* ============================================================
 * P3: TerSafe runtime instruction patching - constructor(150)
 *
 * Full kill chain (based on tombstone SI_TKILL analysis):
 *   detect -> 0x419fdc -> 0x2e7810(dispatch) -> 0x2f29d0(router) ->
 *   0x320d78(kill wrapper) -> 0x3233b8(tgkill call)
 *
 * Strategy: patch ALL nodes in the kill chain, from entry to exit.
 * Timing fix: poll-wait for libtersafe.so (constructor may run before
 * it's loaded when using hijack injection via libtdmqimei.so).
 * ============================================================ */

/* game-process-writable patch log - lives inside game's own data dir */
static void hook_log(const char *msg) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD,
        "/data/data/com.tencent.tmgp.dfm/files/forge_hook.log",
        O_WRONLY | O_CREAT | O_APPEND, 0644);
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

/* full kill chain patch table - ordered from detection entry to tgkill exit */
static const struct { uint64_t off; uint32_t insn; const char *name; } kKillChain[] = {
    {0x419fdcu, 0xD2800000u, "detect_entry MOV X0,#0"},
    {0x419fe0u, 0xD65F03C0u, "detect_entry+4 RET"},
    {0x2e7810u, 0xD65F03C0u, "kill_dispatch RET"},
    {0x2f29d0u, 0xD65F03C0u, "kill_router RET"},
    {0x320d78u, 0xD65F03C0u, "kill_wrapper RET"},
    {0x3233b8u, 0xD65F03C0u, "tgkill_call RET"},
};
#define KILL_CHAIN_N (sizeof(kKillChain)/sizeof(kKillChain[0]))

__attribute__((constructor(150)))
static void _patch_tersafe(void) {
    uintptr_t base = 0;
    char logbuf[160];

    /* poll-wait for libtersafe.so to load (up to 10 seconds)
     * when hijack path is used, libtersafe.so may load before OR after us */
    for (int retry = 0; retry < 50; retry++) {
        base = get_module_base("libtersafe.so");
        if (base) break;
        if (retry == 0) hook_log("[patch] waiting for libtersafe.so...\n");
        usleep(200000);
    }
    if (!base) {
        hook_log("[patch] TIMEOUT: libtersafe.so not loaded after 10s\n");
        return;
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
}

/* ---- P1: seccomp-bpf SIGSYS handler ---- */
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
    const fake_file_t *ff=match(path);
    if(ff&&!(x2&1)){int fd=fake_fd(ff->data,ff->len);if(fd>=0){set_sigsys_x0(uc,(uint64_t)fd);g_sigsys_blocked++;return;}}
    set_sigsys_x0(uc,(uint64_t)-ENOSYS);
}

/* ============================================================
 * P1: seccomp-bpf - kernel-level kill syscall interception
 *
 * Blocks: tgkill(131) sig!=0, tkill(130) sig!=0, kill(129) all signals
 * Allows: sig==0 (thread existence check via pthread_kill)
 * File syscalls continue to TRAP -> SIGSYS handler for path replacement.
 * constructor priority=49 - installed BEFORE any other hooks/patches.
 * ============================================================ */
static struct sock_filter g_bpf_prog[]={
    /* 0-2: architecture check */
    {BPF_LD|BPF_W|BPF_ABS, 0,0,4},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, AUDIT_ARCH_AARCH64},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ALLOW},
    /* 3: load syscall nr */
    {BPF_LD|BPF_W|BPF_ABS, 0,0,0},

    /* ---- tgkill(131): block sig 1-31, allow 0 and real-time (>=32) ---- */
    {BPF_JMP|BPF_JEQ|BPF_K, 0,5, ARM64_NR_TGKILL},
    {BPF_LD|BPF_W|BPF_ABS, 0,0,32},            /* args[2] = sig */
    {BPF_JMP|BPF_JEQ|BPF_K, 4,0, 0},           /* sig==0 -> ALLOW (thread check) */
    {BPF_JMP|BPF_JGE|BPF_K, 2,0, 32},          /* sig>=32 -> ALLOW (RT signals for pthread) */
    {BPF_JMP|BPF_JGT|BPF_K, 0,0, 31},          /* sig>31? -> ALLOW, else -> BLOCK (1-31 fatal) */
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ALLOW},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ERRNO|1}, /* BLOCK fatal sig -> -EPERM */

    /* ---- tkill(130): block sig 1-31, allow 0 and real-time ---- */
    {BPF_JMP|BPF_JEQ|BPF_K, 0,5, ARM64_NR_TKILL},
    {BPF_LD|BPF_W|BPF_ABS, 0,0,24},            /* args[1] = sig (tkill takes 2 args) */
    {BPF_JMP|BPF_JEQ|BPF_K, 4,0, 0},           /* sig==0 -> ALLOW */
    {BPF_JMP|BPF_JGE|BPF_K, 2,0, 32},          /* sig>=32 -> ALLOW (RT signals) */
    {BPF_JMP|BPF_JGT|BPF_K, 0,0, 31},          /* sig>31? -> ALLOW */
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ALLOW},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ERRNO|1}, /* BLOCK tkill fatal -> -EPERM */

    /* ---- kill(129): unconditional block ---- */
    {BPF_JMP|BPF_JEQ|BPF_K, 0,1, ARM64_NR_KILL},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ERRNO|1}, /* BLOCK kill -> -EPERM */

    /* ---- file syscalls -> TRAP -> SIGSYS handler ---- */
    {BPF_LD|BPF_W|BPF_ABS, 0,0,0},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, ARM64_NR_OPENAT},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, ARM64_NR_READLINKAT},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, ARM64_NR_NEWFSTATAT},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, ARM64_NR_OPENAT2},
    {BPF_JMP|BPF_JEQ|BPF_K, 1,0, ARM64_NR_GETDENTS64},
    {BPF_JMP|BPF_JEQ|BPF_K, 0,0, ARM64_NR_FACCESSAT2},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_TRAP},
    {BPF_RET|BPF_K, 0,0, SECCOMP_RET_ALLOW},
};
static struct sock_fprog g_bpf_fprog={.len=sizeof(g_bpf_prog)/sizeof(g_bpf_prog[0]),.filter=g_bpf_prog};

static void install_seccomp(void){
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
        "[seccomp] tgkill+tkill+kill blocked r=%ld errno=%d tsync=%d active=%d\n",
        r, r!=0?errno:0, used_tsync, g_bpf_active);
    if (ln > 0) hook_log(logbuf);
}
/* priority=49 - install seccomp BEFORE any other hooks (no race window for TerSafe) */
__attribute__((constructor(49)))
static void _install_seccomp_cb(void){install_seccomp();}

/* ---- P2: __system_property_get hook ---- */
typedef struct{const char *key;const char *value;}hook_prop_t;
static const hook_prop_t HOOK_PROPS[]={
    /* Samsung Galaxy S10 (SM-G9730 beyond1q) — 与底层 fingerprint 一致 */
    {"ro.product.manufacturer","samsung"},
    {"ro.product.model","SM-G9730"},
    {"ro.product.device","beyond1q"},
    {"ro.product.name","beyond1qltezc"},
    {"ro.build.product","beyond1q"},
    {"ro.product.brand","samsung"},
    {"ro.hardware","qcom"},
    {"ro.board.platform","msmnile"},
    {"ro.product.board","msmnile"},
    {"ro.build.fingerprint","samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"},
    {"ro.build.tags","release-keys"},
    {"ro.build.type","user"},
    {"ro.build.user","dpi"},
    {"ro.build.host","SWDD6847"},
    {"ro.build.description","beyond1qltezc-user 11 RP1A.200720.012 G9730ZCS6FULZ release-keys"},
    {"ro.build.version.sdk","30"},
    {"ro.build.version.release","11"},
    {"ro.build.version.incremental","G9730ZCS6FULZ"},
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
    {"persist.sys.usb.config","adb"},
    {"gsm.version.baseband","G9730ZCS6FULZ"},
    /* 序列号/IMEI — 清空防止云手机特征泄露 */
    {"ro.serialno",""},
    {"ro.boot.serialno",""},
    {"persist.sys.device_name","Redmi K60"},
    {"bluetooth.name","Redmi K60"},
    {"wifi.interface","wlan0"},
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
    {"ro.hardware.gralloc",""},
    {"ro.product.base_version",""},
    {"ro.product.odm.brand",""},
    {"ro.product.odm.device",""},
    {"ro.product.odm.manufacturer",""},
    {"ro.product.odm.model",""},
    {"ro.product.odm.name",""},
    {"ro.product.odm_dlkm.brand",""},
    {"ro.product.odm_dlkm.device",""},
    {"ro.product.odm_dlkm.manufacturer",""},
    {"ro.product.odm_dlkm.model",""},
    {"ro.product.odm_dlkm.name",""},
    {"ro.product.product.brand",""},
    {"ro.product.product.device",""},
    {"ro.product.product.manufacturer",""},
    {"ro.product.product.model",""},
    {"ro.product.product.name",""},
    {"ro.product.ota.host",""},
    {"ro.build.characteristics",""},
    {"ro.build.display.id","UKQ1.231108.001"},
    {"ro.product.build.id","UKQ1.231108.001"},
    {"ro.build.flavor","marble-user"},
    {"ro.product.build.fingerprint","Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {NULL,NULL}
};

typedef int (*hook_prop_get_t)(const char*,char*);
static hook_prop_get_t real_prop_get=NULL;

int __system_property_get(const char *name,char *value){
    if(!real_prop_get)real_prop_get=(hook_prop_get_t)dlsym(RTLD_NEXT,"__system_property_get");
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
    /* 未在 HOOK_PROPS 中的属性 — 记录供分析 */
    forge_audit("prop_get",name);
    return real_prop_get(name,value);
}

/* ---- P2: JNI helpers for B3 ---- */
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
    struct{const char *name;const char *sig;const char *val;}fields[]={
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
    for(int i=0;fields[i].name;i++){
        jfieldID fid=(*env)->GetStaticFieldID(env,build_cls,fields[i].name,fields[i].sig);
        if(!fid){(*env)->ExceptionClear(env);continue;}
        jstring s=(*env)->NewStringUTF(env,fields[i].val);
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
