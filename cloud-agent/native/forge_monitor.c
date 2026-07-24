// ============================================================
// 法器: DeltaForge/cloud-agent/native/forge_monitor.c v5.8
// 描述: 反作弊行为监控器 — 捕获游戏读了哪些文件/属性，分析封号逻辑
//   1. inotify 监听游戏数据目录
//   2. /proc/[pid]/fd 枚举已打开文件
//   3. /proc/[pid]/net/tcp 检测上报连接
//   4. 尾读 forge_audit.log (libforgehook.so 写入的覆盖缺口)
// 编译: aarch64-linux-android21-clang -static -Os -o forge_monitor forge_monitor.c
// 用法: ./forge_monitor [-v] [-o /data/local/tmp/forge_monitor.log]
// ============================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <stdint.h>

#define TARGET_PKG   "com.tencent.tmgp.dfm"
#define APP_DATA     "/data/data/" TARGET_PKG
#define MON_LOG      "/data/local/tmp/forge_monitor.log"
#define AUDIT_LOG    "/data/data/com.tencent.tmgp.dfm/files/forge_audit.log"
#define POLL_MS      500

static const char *WATCH_DIRS[] = {
    APP_DATA "/files/ano_tmp",
    APP_DATA "/files/tdm_tmp",
    APP_DATA "/files/qm",
    APP_DATA "/shared_prefs",
    APP_DATA "/databases",
    APP_DATA "/files/perfsight",
    "/sdcard/Tencent/GameDetect",
    "/sdcard/Tencent/GameSecurity",
    NULL
};

/* 出现这些词的文件访问标记为 ALERT */
static const char *KEYWORDS[] = {
    "tersafe","tss","ace","qimei","tgpa","tdm","hawk","crashsight",
    "gcloud","msdk","gpmsdk","beacon","detect","security","report",
    "ban","frozen","kick","emulator","virtual","cloud","qemu","vbox",
    "imei","serial","device_id","hardware_id","frida","xposed","magisk",
    NULL
};

static int        g_verbose = 0;
static FILE      *g_log     = NULL;
static volatile int g_run   = 1;
static pid_t      g_pid     = 0;

#define MAX_SEEN 512
static char g_seen[MAX_SEEN][512];
static int  g_seen_n = 0;

/* ---- log ---- */
static void mlog(const char *lv, const char *fmt, ...) {
    char buf[1024]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    time_t t = time(NULL); struct tm *tm = localtime(&t); char ts[24];
    strftime(ts, sizeof(ts), "%m-%d %H:%M:%S", tm);
    if (g_log) { fprintf(g_log,"[%s][%s] %s\n", ts, lv, buf); fflush(g_log); }
    if (g_verbose || lv[0]=='A') fprintf(stderr,"[%s][%s] %s\n", ts, lv, buf);
}
#define INFO(f,...) mlog("INFO ",f,##__VA_ARGS__)
#define ALRT(f,...) mlog("ALERT",f,##__VA_ARGS__)
#define DBG(f,...)  do{if(g_verbose)mlog("DBG  ",f,##__VA_ARGS__);}while(0)

/* ---- helpers ---- */
static pid_t find_pid(void) {
    DIR *d = opendir("/proc"); if (!d) return 0;
    struct dirent *e; pid_t r = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0]<'0'||e->d_name[0]>'9') continue;
        char p[64]; snprintf(p,sizeof(p),"/proc/%s/cmdline",e->d_name);
        int fd = open(p,O_RDONLY); if (fd<0) continue;
        char buf[256]={0}; read(fd,buf,sizeof(buf)-1); close(fd);
        if (strstr(buf,TARGET_PKG)) { r=(pid_t)atoi(e->d_name); break; }
    }
    closedir(d); return r;
}

static int interesting(const char *s) {
    if (!s) return 0;
    char lo[512]; size_t l=strlen(s); if(l>=sizeof(lo))l=sizeof(lo)-1;
    for (size_t i=0;i<l;i++) lo[i]=(s[i]>='A'&&s[i]<='Z')?s[i]+32:s[i];
    lo[l]='\0';
    for (const char **k=KEYWORDS;*k;k++) if (strstr(lo,*k)) return 1;
    return 0;
}

static int seen(const char *p) {
    for (int i=0;i<g_seen_n;i++) if (!strcmp(g_seen[i],p)) return 1;
    if (g_seen_n<MAX_SEEN) { strncpy(g_seen[g_seen_n++],p,511); g_seen[g_seen_n-1][511]='\0'; }
    return 0;
}

/* ---- fd scan ---- */
static void scan_fds(pid_t pid) {
    char dir[64]; snprintf(dir,sizeof(dir),"/proc/%d/fd",pid);
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *e;
    while ((e=readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char fp[128],tgt[512]={0}; snprintf(fp,sizeof(fp),"%s/%s",dir,e->d_name);
        ssize_t n = readlink(fp,tgt,sizeof(tgt)-1); if (n<=0) continue; tgt[n]='\0';
        if (tgt[0]!='/') continue;
        if (seen(tgt)) continue;
        if (interesting(tgt)) ALRT("FD_OPEN fd=%s path=%s",e->d_name,tgt);
        else DBG("FD_OPEN fd=%s path=%s",e->d_name,tgt);
    }
    closedir(d);
}

/* ---- maps scan — 检测可疑注入库 ---- */
static char g_last_suspicious[512]="";
static void scan_maps(pid_t pid) {
    char mf[64]; snprintf(mf,sizeof(mf),"/proc/%d/maps",pid);
    FILE *f = fopen(mf,"r"); if (!f) return;
    char line[1024];
    while (fgets(line,sizeof(line),f)) {
        if (strstr(line,"libdetect")||strstr(line,"libemulator")||strstr(line,"libsandbox")) {
            char *p=strchr(line,'/'); if (!p) continue;
            char *nl=strchr(p,'\n'); if(nl)*nl='\0';
            if (strcmp(p,g_last_suspicious)!=0) {
                ALRT("SUSPICIOUS_LIB_IN_MAPS: %s",p);
                strncpy(g_last_suspicious,p,sizeof(g_last_suspicious)-1);
            }
        }
    }
    fclose(f);
}

/* ---- net/tcp scan — 检测上报连接 ---- */
/* 已知 TDM/CrashSight 域名解析出的 IP 前缀(hex little-endian) */
static const char *AC_IP_PREFIXES[] = {
    "76EF",  /* 118.239.x.x tdm.qq.com    */
    "3BA8",  /* 59.168.x.x  tdm.3g.qq.com */
    "7B19",  /* 123.25.x.x  gcloud         */
    NULL
};

static void scan_net(pid_t pid) {
    char nf[64]; snprintf(nf,sizeof(nf),"/proc/%d/net/tcp",pid);
    FILE *f = fopen(nf,"r"); if (!f) return;
    char line[512]; fgets(line,sizeof(line),f); /* skip header */
    while (fgets(line,sizeof(line),f)) {
        char rem[32],st[4];
        if (sscanf(line," %*s %*s %31s %3s",rem,st)<2) continue;
        if (strcmp(st,"01")!=0) continue; /* ESTABLISHED only */
        for (const char **pre=AC_IP_PREFIXES;*pre;pre++) {
            if (strncmp(rem,*pre,strlen(*pre))==0)
                ALRT("AC_REPORT_CONN remote=%s — 疑似上报检测数据",rem);
        }
    }
    fclose(f);
}

/* ---- status — TracerPid 检测 ---- */
static void check_tracer(pid_t pid) {
    char sf[64]; snprintf(sf,sizeof(sf),"/proc/%d/status",pid);
    FILE *f = fopen(sf,"r"); if (!f) return;
    char line[256];
    while (fgets(line,sizeof(line),f)) {
        if (strncmp(line,"TracerPid:",10)==0) {
            if (atoi(line+10)!=0) ALRT("GAME_IS_TRACED pid=%d tracer=%d",pid,atoi(line+10));
            break;
        }
    }
    fclose(f);
}

/* ---- audit log 尾读 (libforgehook 写入) ---- */
static long g_audit_off=0;
static void tail_audit(void) {
    FILE *f=fopen(AUDIT_LOG,"r"); if (!f) return;
    fseek(f,g_audit_off,SEEK_SET);
    char line[1024];
    while (fgets(line,sizeof(line),f)) {
        if (strstr(line,"[GAP]"))  /* 未覆盖的访问 */
            ALRT("COVERAGE_GAP %s",line);
    }
    g_audit_off=ftell(f); fclose(f);
}

/* ---- inotify ---- */
static int setup_inotify(void) {
    int ifd=inotify_init1(IN_NONBLOCK); if (ifd<0) return -1;
    for (const char **d=WATCH_DIRS;*d;d++) {
        int wd=inotify_add_watch(ifd,*d,IN_CREATE|IN_OPEN|IN_MODIFY|IN_DELETE|IN_ACCESS);
        if (wd>=0) DBG("watch: %s",*d);
    }
    return ifd;
}

static void proc_inotify(int ifd) {
    char buf[4096] __attribute__((aligned(8)));
    ssize_t n=read(ifd,buf,sizeof(buf)); if(n<=0) return;
    for (char *p=buf; p<buf+n; ) {
        struct inotify_event *ev=(struct inotify_event *)p;
        if (ev->len>0) {
            const char *et = (ev->mask&IN_CREATE)?"CREATE":(ev->mask&IN_OPEN)?"OPEN":
                             (ev->mask&IN_MODIFY)?"MODIFY":(ev->mask&IN_DELETE)?"DELETE":"ACCESS";
            if (interesting(ev->name)) ALRT("INOTIFY[%s] %s",et,ev->name);
            else DBG("INOTIFY[%s] %s",et,ev->name);
        }
        p+=sizeof(struct inotify_event)+ev->len;
    }
}

static void on_sig(int s){(void)s;g_run=0;}

/* ============= main ============= */
int main(int argc, char **argv) {
    const char *logpath=MON_LOG;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"-v")) g_verbose=1;
        else if (!strcmp(argv[i],"-o")&&i+1<argc) logpath=argv[++i];
    }
    g_log=fopen(logpath,"a"); if (!g_log){perror("log");return 1;}
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);
    INFO("forge_monitor v5.8 start, log=%s",logpath);

    int ifd=setup_inotify();
    if (ifd<0) INFO("inotify unavailable — fd-only mode");

    while (g_run) {
        if (g_pid<=0||kill(g_pid,0)!=0) {
            g_pid=find_pid();
            if (g_pid>0) INFO("game found pid=%d",g_pid);
            else { usleep(2000000); continue; }
        }
        scan_fds(g_pid);
        scan_maps(g_pid);
        scan_net(g_pid);
        check_tracer(g_pid);
        tail_audit();
        if (ifd>=0) {
            fd_set fds; FD_ZERO(&fds); FD_SET(ifd,&fds);
            struct timeval tv={0,POLL_MS*1000};
            if (select(ifd+1,&fds,NULL,NULL,&tv)>0) proc_inotify(ifd);
            else usleep(POLL_MS*1000);
        } else {
            usleep(POLL_MS*1000);
        }
    }
    INFO("forge_monitor stopped");
    if(ifd>=0) close(ifd);
    fclose(g_log);
    return 0;
}
