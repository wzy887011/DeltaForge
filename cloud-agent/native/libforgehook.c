// ============================================================
// DeltaForge/cloud-agent/native/libforgehook.c v5.0
// Shared library — hook __system_property_get, fopen/open, seccomp-bpf, JNI
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
#define BPF_K    0x00

/* ---- maps hide ---- */
__attribute__((constructor))
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

/* ---- chainload real Qimei (B1: read /data/local/tmp/chainload_path.txt) ---- */
__attribute__((constructor(50)))
static void _chainload_real_qimei(void) {
    FILE *fp=fopen("/data/local/tmp/chainload_path.txt","r");
    if(!fp){
        FILE *log=fopen("/data/local/tmp/forge.log","a");
        if(log){fprintf(log,"[!] chainload: chainload_path.txt not found\n");fflush(log);fclose(log);}
        return;
    }
    char lib_path[512]={0};
    fgets(lib_path,sizeof(lib_path),fp);
    fclose(fp);
    lib_path[strcspn(lib_path,"\r\n")]=0;
    void *h=dlopen(lib_path,RTLD_NOW|RTLD_GLOBAL);
    FILE *log=fopen("/data/local/tmp/forge.log","a");
    if(log){
        if(h)fprintf(log,"[+] chainload: %s (handle=%p)\n",lib_path,h);
        else fprintf(log,"[!] chainload: FAILED %s (%s)\n",lib_path,dlerror());
        fflush(log);fclose(log);
    }
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
    {NULL,NULL,0}
};

static const char *HIDDEN[]={
    "/sys/class/misc/qemu","/sys/class/misc/vbox",
    "/sys/class/misc/vhost","/sys/bus/virtio",
    "/sys/bus/virtio/devices","/sys/bus/virtio/drivers",
    "/sys/devices/virtual","/sys/firmware/qemu",
    "/sys/hypervisor",
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
    "/data/local/tmp/inject","/dev/qemu_pipe",
    "/dev/socket/qemud","/dev/goldfish_pipe",
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
    const fake_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=fake_fd(f->data,f->len);if(fd>=0)return fd;}
    return _open(p,flags,m);
}

int openat(int dir,const char *p,int flags,...){
    INIT();mode_t m=0;
    if(flags&O_CREAT){va_list a;va_start(a,flags);m=(mode_t)va_arg(a,int);va_end(a);}
    if(hidden(p)){errno=ENOENT;return -1;}
    const fake_file_t *f=match(p);
    if(f&&!(flags&O_WRONLY)){int fd=fake_fd(f->data,f->len);if(fd>=0)return fd;}
    return _openat(dir,p,flags,m);
}

FILE *fopen(const char *p,const char *m){
    INIT();
    if(hidden(p)){errno=ENOENT;return NULL;}
    const fake_file_t *f=match(p);
    if(f&&m[0]=='r'){FILE *fp=fmemopen((void*)f->data,f->len,m);if(fp)return fp;}
    return _fopen(p,m);
}

int access(const char *p,int m){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _access(p,m);}
int stat(const char *p,struct stat *b){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _stat(p,b);}
int lstat(const char *p,struct stat *b){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _lstat(p,b);}
ssize_t readlink(const char *p,char *buf,size_t sz){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _readlink(p,buf,sz);}
ssize_t readlinkat(int dir,const char *p,char *buf,size_t sz){INIT();if(hidden(p)){errno=ENOENT;return -1;}return _readlinkat(dir,p,buf,sz);}

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

static struct sock_filter g_bpf_prog[]={
    {BPF_LD|BPF_W|BPF_ABS,0,0,4},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,AUDIT_ARCH_AARCH64},
    {BPF_RET|BPF_K,0,0,SECCOMP_RET_ALLOW},
    {BPF_LD|BPF_W|BPF_ABS,0,0,0},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,ARM64_NR_OPENAT},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,ARM64_NR_READLINKAT},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,ARM64_NR_NEWFSTATAT},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,ARM64_NR_OPENAT2},
    {BPF_JMP|BPF_JEQ|BPF_K,1,0,ARM64_NR_GETDENTS64},
    {BPF_JMP|BPF_JEQ|BPF_K,0,0,ARM64_NR_FACCESSAT2},
    {BPF_RET|BPF_K,0,0,SECCOMP_RET_TRAP},
    {BPF_RET|BPF_K,0,0,SECCOMP_RET_ALLOW},
};
static struct sock_fprog g_bpf_fprog={.len=sizeof(g_bpf_prog)/sizeof(g_bpf_prog[0]),.filter=g_bpf_prog};

static void install_seccomp(void){
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sa.sa_sigaction=sigsys_handler;
    sa.sa_flags=SA_SIGINFO|SA_RESTART|SA_NODEFER;
    sigaction(SIGSYS,&sa,NULL);
    if(prctl(SECCOMP_SET_MODE_FILTER,0UL,&g_bpf_fprog)!=0){g_bpf_active=0;return;}
    g_bpf_active=1;
}
__attribute__((constructor(101)))
static void _install_seccomp_cb(void){install_seccomp();}

/* ---- P2: __system_property_get hook ---- */
typedef struct{const char *key;const char *value;}hook_prop_t;
static const hook_prop_t HOOK_PROPS[]={
    {"ro.product.manufacturer","Xiaomi"},
    {"ro.product.model","23049RAD8C"},
    {"ro.product.device","marble"},
    {"ro.product.name","marble"},
    {"ro.build.product","marble"},
    {"ro.product.brand","Xiaomi"},
    {"ro.hardware","qcom"},
    {"ro.board.platform","kalama"},
    {"ro.product.board","kalama"},
    {"ro.build.fingerprint","Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {"ro.build.tags","release-keys"},
    {"ro.build.type","user"},
    {"ro.build.user","builder"},
    {"ro.build.host","m1-xm-bsp-01"},
    {"ro.build.description","marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
    {"ro.build.version.sdk","34"},
    {"ro.build.version.release","14"},
    {"ro.build.version.incremental","V816.0.9.0.UMRCNXM"},
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
    {"gsm.version.baseband","MPSS.TH.5.0-05076-OmniGen_PACK-1"},
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
            if(e->value[0]){size_t l=strlen(e->value);if(value){memcpy(value,e->value,l);value[l]='\0';}return (int)l;}
            return 0;
        }
    }
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
        {"MANUFACTURER","Ljava/lang/String;","Xiaomi"},
        {"MODEL","Ljava/lang/String;","23049RAD8C"},
        {"BRAND","Ljava/lang/String;","Xiaomi"},
        {"DEVICE","Ljava/lang/String;","marble"},
        {"PRODUCT","Ljava/lang/String;","marble"},
        {"HARDWARE","Ljava/lang/String;","qcom"},
        {"BOARD","Ljava/lang/String;","kalama"},
        {"FINGERPRINT","Ljava/lang/String;","Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
        {"TAGS","Ljava/lang/String;","release-keys"},
        {"TYPE","Ljava/lang/String;","user"},
        {"USER","Ljava/lang/String;","builder"},
        {"HOST","Ljava/lang/String;","m1-xm-bsp-01"},
        {"DISPLAY","Ljava/lang/String;","marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
        {"BOOTLOADER","Ljava/lang/String;","unknown"},
        {"RADIO","Ljava/lang/String;",""},
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
static void _cleanup(void){}
