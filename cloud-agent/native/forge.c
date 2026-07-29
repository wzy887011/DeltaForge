// ============================================================
// cloud-agent/native/forge.c v8.7
// DeltaForge — 游戏运行环境管理主控
// 编译: clang -pie -Os -Wall forge.c patch_loader.c -o forge
// 关键修复 (v6.0):
//   - safe_verify_and_write: 写入前读原始指令校验
//   - libtersafe.so 不存在时拒绝写入 (防向 0 偏移写内存)
//   - BSS 段范围验证 (0xC00000 保守上界)
//   - WRITE_FAIL_ABORT_THRESHOLD 0: any write failure aborts the transaction
//   - 渐进退避轮询 (100ms→2000ms)
//   - inject_hook 失败检查 + signal handlers
// ============================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#ifndef __NR_pread64
#define __NR_pread64  67
#endif
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypt_strings.h"
#include "patch_loader.h"
#include <sys/un.h>
#include <sys/mount.h>

/* ============= TASK-06: validated patch table loaded from JSON ============= */
#define FORGE_PATCH_JSON "/data/local/tmp/forge_patches.json"
static patch_table_t g_dyn_table;   /* 动态加载结果 */
static int           g_dyn_loaded = 0;

/* JSON is the only runtime source; no compiled offset fallback. */
#define EXPECTED_TERSAFE_PATCH_COUNT 75
#define EXPECTED_TERSAFE_BSS_COUNT   40
#define DYN_TERSAFE_PATCHES (g_dyn_table.tersafe_patches)
#define DYN_TERSAFE_COUNT   ((size_t)g_dyn_table.tersafe_count)
#define DYN_BSS_OFFSETS     (g_dyn_table.tersafe_bss)
#define DYN_BSS_COUNT       ((size_t)g_dyn_table.bss_count)
#define DYN_UE4_PATCHES     (g_dyn_table.ue4_patches)
#define DYN_UE4_COUNT       ((size_t)g_dyn_table.ue4_count)

static void load_dyn_table(void);

/* [v7.1 P2] 垃圾指令注入 — 防静态特征码匹配 */
#define JUNK_INSN() __asm__ __volatile__( \
    "and x0, x0, x0\n\t" \
    "orr x1, x1, xzr\n\t" \
    ::: "memory")

/* ============= 配置项 ============= */
#define TARGET_PKG          "com.tencent.tmgp.dfm"
#define APP_DATA            "/data/data/" TARGET_PKG

/* 控制服务器地址 (手机 app 通过 adb forward 连接) */
#define CTRL_HOST           "127.0.0.1"
#define CTRL_PORT           9510
#define FORGE_VERSION       "8.7"
#define FORGE_VERSION_STR  "DeltaForge forge v8.7"
#define FORGE_LOG           "/data/local/tmp/forge.log"
#define DETECT_LOG          "/data/local/tmp/detect_now.log"

/* 安全阈值 */
#define WRITE_FAIL_ABORT_THRESHOLD 0   /* fail closed on any guarded write error */
#define BACKOFF_BASE_MS    100
#define BACKOFF_MAX_MS     2000

/* ============= TASK-01: libtersafe.so ELF build-id 版本绑定 =============
 * 空字符串 = 跳过校验（首次部署时先跑一次抓 id 再填）
 * 非空 = 必须与磁盘文件的 .note.gnu.build-id 完全匹配才允许 patch
 * 填法: 在游戏加载后运行 `sha1sum /proc/<pid>/maps` 找到 libtersafe 路径，
 *       再 `readelf -n libtersafe.so | grep "Build ID"` 得到十六进制串填入此处
 */
#define EXPECTED_TERSAFE_BUILD_ID  "d70d7926094ae39a46745c12ddcc1877641f82e8"

static int elf_get_build_id(const char *elf_path, char *hex_out, size_t hex_sz);
static int get_so_disk_path(pid_t pid, const char *soname, char *out, size_t out_sz);
static int verify_tersafe_version(pid_t pid);
static int run_cmd(const char *argv[]);  /* forward for start_logcat */

static void start_logcat(void) {
    /* kill existing logcat */
    const char *kill_argv[] = {"/system/bin/killall", "logcat", NULL};
    run_cmd(kill_argv);
    usleep(500000);

    /* clear logcat buffer */
    const char *clear_argv[] = {"/system/bin/logcat", "-c", NULL};
    run_cmd(clear_argv);

    /* spawn: logcat -v time | grep ... > DETECT_LOG & */
    pid_t p = fork();
    if (p == 0) {
        int out = open(DETECT_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out >= 0) { dup2(out, 1); dup2(out, 2); close(out); }
        int pfd[2];
        if (pipe(pfd) != 0) _exit(1);
        pid_t lc = fork();
        if (lc == 0) {
            close(pfd[0]); dup2(pfd[1], 1); close(pfd[1]);
            const char *a[] = {"/system/bin/logcat", "-v", "time", NULL};
            execv(a[0], (char *const *)a); _exit(127);
        }
        close(pfd[1]); dup2(pfd[0], 0); close(pfd[0]);
        const char *a[] = {"/system/bin/grep", "-iE",
            "tersafe|TSS|ACE|Qimei|TGPA|GCloud|MSDK|TDM|"
            "anti.cheat|forbid|ban|frozen|kicked|emulator|"
            "fingerprint|hardware|manufacturer|device_id",
            NULL};
        execv(a[0], (char *const *)a); _exit(127);
    }
    fprintf(stderr, "[+] monitor log: %s\n", DETECT_LOG);
}

static int do_prepare(void);
static int do_launch(void);

/* ============= 日志宏 ============= */
static int g_verbose = 0;
static FILE *g_logfile = NULL;

#define OK(fmt, ...)  do { \
    if (g_logfile) { fprintf(g_logfile, "[+] " fmt "\n", ##__VA_ARGS__); fflush(g_logfile); } \
    fprintf(stderr, "\033[32m[+] " fmt "\033[0m\n", ##__VA_ARGS__); \
} while(0)
#define WARN(fmt, ...) do { \
    if (g_logfile) { fprintf(g_logfile, "[!] " fmt "\n", ##__VA_ARGS__); fflush(g_logfile); } \
    fprintf(stderr, "\033[33m[!] " fmt "\033[0m\n", ##__VA_ARGS__); \
} while(0)
#define ERR(fmt, ...) do { \
    if (g_logfile) { fprintf(g_logfile, "[-] " fmt "\n", ##__VA_ARGS__); fflush(g_logfile); } \
    fprintf(stderr, "\033[31m[-] " fmt "\033[0m\n", ##__VA_ARGS__); \
} while(0)

/* ========================================================================== */
/* 后段函数实现 — 依赖上方的日志宏和静态表，放在此处避免前向引用 OK/WARN/ERR     */
/* ========================================================================== */

static int valid_build_id(const char *value) {
    if (!value || strlen(value) != 40) return 0;
    for (size_t i = 0; i < 40; i++) {
        if (!isxdigit((unsigned char)value[i])) return 0;
    }
    return 1;
}

static int validate_code_entries(const char *name, const patch_entry_t *entries,
                                 int count, uint64_t max_offset) {
    for (int i = 0; i < count; i++) {
        if (!entries[i].has_expected || entries[i].offset == 0
            || (entries[i].offset & 3U) != 0 || entries[i].offset > max_offset) {
            ERR("[patch_loader] %s[%d] invalid guard/alignment/range", name, i);
            return 0;
        }
        for (int j = 0; j < i; j++) {
            if (entries[i].offset == entries[j].offset) {
                ERR("[patch_loader] %s duplicate offset 0x%llx", name,
                    (unsigned long long)entries[i].offset);
                return 0;
            }
        }
    }
    return 1;
}

static int validate_bss_entries(const uint64_t *entries, int count) {
    for (int i = 0; i < count; i++) {
        if (entries[i] == 0 || (entries[i] & 3U) != 0 || entries[i] > 0xC00000) {
            ERR("[patch_loader] bss[%d] invalid alignment/range", i);
            return 0;
        }
        for (int j = 0; j < i; j++) {
            if (entries[i] == entries[j]) {
                ERR("[patch_loader] duplicate bss offset 0x%llx",
                    (unsigned long long)entries[i]);
                return 0;
            }
        }
    }
    return 1;
}

/* TASK-06: load a guarded JSON table; any failure disables memory writes. */
static void load_dyn_table(void) {
    patch_loader_free(&g_dyn_table);
    g_dyn_loaded = 0;
    if (patch_loader_load(FORGE_PATCH_JSON, &g_dyn_table)) {
        int guarded = valid_build_id(g_dyn_table.build_id)
            && g_dyn_table.tersafe_count == EXPECTED_TERSAFE_PATCH_COUNT
            && g_dyn_table.bss_count == EXPECTED_TERSAFE_BSS_COUNT;
        if (!guarded) {
            ERR("[patch_loader] unexpected table shape: tersafe=%d/%d bss=%d/%d build_id=%s",
                g_dyn_table.tersafe_count, EXPECTED_TERSAFE_PATCH_COUNT,
                g_dyn_table.bss_count, EXPECTED_TERSAFE_BSS_COUNT,
                valid_build_id(g_dyn_table.build_id) ? "valid" : "invalid");
        }
        guarded = guarded && validate_code_entries("tersafe",
            g_dyn_table.tersafe_patches, g_dyn_table.tersafe_count, 0xC00000);
        guarded = guarded && validate_bss_entries(
            g_dyn_table.tersafe_bss, g_dyn_table.bss_count);
        if (g_dyn_table.ue4_count > 0) {
            guarded = guarded && valid_build_id(g_dyn_table.ue4_build_id)
                && validate_code_entries("ue4", g_dyn_table.ue4_patches,
                    g_dyn_table.ue4_count, 0x40000000);
        }
        if (!guarded) {
            ERR("[patch_loader] rejected unguarded patch table");
            patch_loader_free(&g_dyn_table);
            return;
        }
        g_dyn_loaded = 1;
        OK("[patch_loader] JSON 加载成功: tersafe=%d bss=%d ue4=%d build_id=%s",
           g_dyn_table.tersafe_count, g_dyn_table.bss_count, g_dyn_table.ue4_count,
           g_dyn_table.build_id[0] ? g_dyn_table.build_id : "(empty)");
    } else {
        ERR("[patch_loader] 未找到 %s 或解析失败，内存 patch 将保持禁用", FORGE_PATCH_JSON);
    }
}

/* TASK-01: 从磁盘 ELF 文件读取 .note.gnu.build-id */
static int elf_get_build_id(const char *elf_path, char *hex_out, size_t hex_sz) {
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char ehdr[64];
    if (read(fd, ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr)
        || ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
        { close(fd); return 0; }
    int is64 = (ehdr[4] == 2);
    uint64_t shoff; uint16_t shentsize, shnum, shstrndx;
    if (is64) {
        shoff=*(uint64_t*)(ehdr+40); shentsize=*(uint16_t*)(ehdr+58);
        shnum=*(uint16_t*)(ehdr+60); shstrndx=*(uint16_t*)(ehdr+62);
    } else {
        shoff=*(uint32_t*)(ehdr+32); shentsize=*(uint16_t*)(ehdr+46);
        shnum=*(uint16_t*)(ehdr+48); shstrndx=*(uint16_t*)(ehdr+50);
    }
    if (!shoff||!shnum||!shstrndx) { close(fd); return 0; }
    uint64_t shstr_off, shstr_sz;
    off_t seek_pos = (off_t)(shoff+(uint64_t)shstrndx*shentsize);
    if (lseek(fd,seek_pos,SEEK_SET)!=seek_pos) { close(fd); return 0; }
    unsigned char shhdr[64]={0};
    if (read(fd,shhdr,(size_t)shentsize)<=0) { close(fd); return 0; }
    if (is64) { shstr_off=*(uint64_t*)(shhdr+24); shstr_sz=*(uint64_t*)(shhdr+32); }
    else       { shstr_off=*(uint32_t*)(shhdr+16); shstr_sz=*(uint32_t*)(shhdr+20); }
    if (shstr_sz>65536) shstr_sz=65536;
    char *shstrtab=(char*)malloc((size_t)shstr_sz+1);
    if (!shstrtab) { close(fd); return 0; }
    lseek(fd,(off_t)shstr_off,SEEK_SET);
    ssize_t nr=read(fd,shstrtab,(size_t)shstr_sz);
    if (nr>0) shstrtab[nr]='\0'; else { free(shstrtab); close(fd); return 0; }
    int result=0;
    for (uint16_t si=0; si<shnum&&!result; si++) {
        seek_pos=(off_t)(shoff+(uint64_t)si*shentsize);
        if (lseek(fd,seek_pos,SEEK_SET)!=seek_pos) break;
        unsigned char sh[64]={0};
        if (read(fd,sh,(size_t)shentsize)<=0) break;
        uint32_t sh_name,sh_type; uint64_t sh_off,sh_size;
        if (is64) {
            sh_name=*(uint32_t*)(sh+0); sh_type=*(uint32_t*)(sh+4);
            sh_off=*(uint64_t*)(sh+24); sh_size=*(uint64_t*)(sh+32);
        } else {
            sh_name=*(uint32_t*)(sh+0); sh_type=*(uint32_t*)(sh+4);
            sh_off=*(uint32_t*)(sh+16); sh_size=*(uint32_t*)(sh+20);
        }
        if (sh_type!=7||sh_name>=(uint32_t)shstr_sz) continue;
        if (strncmp(shstrtab+sh_name,".note.gnu.build-id",18)!=0) continue;
        if (sh_size<16||sh_size>256) continue;
        unsigned char note[256]={0};
        lseek(fd,(off_t)sh_off,SEEK_SET);
        if (read(fd,note,(size_t)sh_size)<=0) break;
        uint32_t namesz=*(uint32_t*)(note+0), descsz=*(uint32_t*)(note+4);
        uint32_t desc_off=12+((namesz+3)&~3u);
        if (desc_off+descsz>(uint32_t)sh_size||descsz==0) break;
        static const char hx[]="0123456789abcdef";
        for (uint32_t bi=0; bi<descsz&&bi*2+2<(uint32_t)hex_sz; bi++) {
            hex_out[bi*2+0]=hx[(note[desc_off+bi]>>4)&0xF];
            hex_out[bi*2+1]=hx[note[desc_off+bi]&0xF];
        }
        hex_out[descsz*2]='\0'; result=(int)descsz;
    }
    free(shstrtab); close(fd);
    return result;
}

static int get_so_disk_path(pid_t pid, const char *soname,
                             char *out, size_t out_sz) {
    char maps_path[64];
    snprintf(maps_path,sizeof(maps_path),"/proc/%d/maps",pid);
    FILE *f=fopen(maps_path,"r"); if (!f) return 0;
    char line[1024]; int found=0;
    while (fgets(line,sizeof(line),f)&&!found) {
        if (!strstr(line,soname)) continue;
        char *slash=strchr(line,'/'); if (!slash) continue;
        size_t len=strlen(slash);
        while (len>0&&(slash[len-1]=='\n'||slash[len-1]=='\r'||slash[len-1]==' ')) len--;
        if (len>0&&len<out_sz) { memcpy(out,slash,len); out[len]='\0'; found=1; }
    }
    fclose(f); return found;
}

static int verify_module_version(pid_t pid, const char *soname,
                                 const char *expected) {
    if (!valid_build_id(expected)) return 0;
    char so_path[512]={0};
    if (!get_so_disk_path(pid,soname,so_path,sizeof(so_path))) {
        ERR("[version] cannot locate %s disk path", soname);
        return 0;
    }
    char build_id[128]={0};
    if (elf_get_build_id(so_path,build_id,sizeof(build_id))==0) {
        ERR("[version] cannot read ELF build-id: %s", so_path);
        return 0;
    }
    OK("[version] %s build-id: %s (expect: %s)", soname, build_id, expected);
    if (strcmp(build_id,expected)!=0) {
        ERR("[version] %s build-id mismatch; patch table rejected", soname);
        return 0;
    }
    OK("[version] %s build-id verified", soname);
    return 1;
}

static int verify_tersafe_version(pid_t pid) {
    const char *expected = g_dyn_loaded && g_dyn_table.build_id[0]
        ? g_dyn_table.build_id : EXPECTED_TERSAFE_BUILD_ID;
    return verify_module_version(pid, "libtersafe.so", expected);
}

/* ============= 内存调整条目 ============= */

/* --- libtersafe.so 代码段调整，67 处 (含检测链 6) ---
 * 基于 delta_force_detection_final_static_report.md 中的 offset 表
 * 0x2A1F03FF = MOV W0, #0x0FF → 返回 W0=255 (模拟检测通过)
 * 0xD61F03C0 = BR X30 → 直接返回 (跳过函数体)
 * 0xD65F03C0 = RET → 空函数返回
 * 0x1400000X = B #offset → 无条件跳转
 * 0x38400XXX = LDRB Wx, [Xsp, #N] → 改为读取栈偏移(值趋于0), 原指令读取文件/proc节点
 */
/* Historical tables are retained only as review notes. They are never compiled. */
#if 0
static const patch_entry_t kTersafePatches[] = {
    {0x5137C0, 0x2A1F03FF}, {0x516640, 0x2A1F03FF}, {0x526ED0, 0x2A1F03FF},
    {0x4CDB04, 0x14000009}, {0x4CDB34, 0x14000008}, {0x50E380, 0xD61F03C0},
    {0x2E17C4, 0xD61F03C0}, {0x39B1CC, 0x2A1F03FF}, {0x2F0D44, 0x2A1F03FF},
    {0x43B1D0, 0x2A1F03FF}, {0x203304, 0xD65F03C0}, {0x41E774, 0x2A1F03FF},
    {0x4409F8, 0x2A1F03FF}, {0x440C10, 0x2A1F03FF}, {0x4600C8, 0x2A1F03FF},
    {0x460168, 0x2A1F03FF}, {0x20B2DC, 0xD61F03C0}, {0x2872E8, 0x3840050A},
    {0x287DCC, 0x38400509}, {0x288418, 0x38400509}, {0x290554, 0x38400509},
    {0x2AA4D0, 0x38400408}, {0x2AA4FC, 0x38400408}, {0x2AA658, 0x38400408},
    {0x2AA684, 0x38400408}, {0x2AA8F0, 0x38400408}, {0x2AA91C, 0x38400408},
    {0x2AAA48, 0x38400408}, {0x2AAA74, 0x38400408}, {0x2F08F8, 0x38400509},
    {0x2F0C4C, 0x38400509}, {0x2F10A8, 0x38400428}, {0x2F1128, 0x38400509},
    {0x2F1194, 0x38400568}, {0x2F13D8, 0x38400509}, {0x2F1458, 0x38400509},
    {0x2F15F8, 0x38400509}, {0x2F1678, 0x38400509}, {0x477860, 0x38400509},
    {0x479D74, 0x38400509}, {0x479D9C, 0x38400509}, {0x47DCEC, 0x38400748},
    {0x4803BC, 0x38400408}, {0x486230, 0x38400509}, {0x48A9C0, 0x384006A8},
    {0x48A9D8, 0x384006A8}, {0x48A9F0, 0x384006A8}, {0x4A46C4, 0x3840050A},
    {0x4A49FC, 0x3840050A}, {0x4CA4BC, 0x38400509}, {0x4D9FA8, 0x38400688},
    {0x503060, 0x38400509}, {0x508C6C, 0x38400748}, {0x508CB4, 0x38400748},
    {0x508CE8, 0x384006A8}, {0x50A81C, 0x38400509}, {0x50A92C, 0x38400509},
    {0x50A95C, 0x38400509}, {0x50A9BC, 0x38400503}, {0x50B704, 0x3840050A},
    {0x50E370, 0xD65F03C0},
    /* 检测链完整覆盖 - 6 节点从检测入口到 tgkill 出口 */
    {0x419FDC, 0xD65F03C0},  /* detect entry -> RET (与tersafe自修复值相同，消除翻转) */
    {0x419FE0, 0xD65F03C0},  /* detect+4 -> RET */
    {0x2E7810, 0xD65F03C0},  /* dispatch -> RET */
    {0x2F29D0, 0xD65F03C0},  /* router -> RET */
    {0x320D78, 0xD65F03C0},  /* wrapper -> RET */
    {0x3233B8, 0xD65F03C0},  /* tgkill call site -> RET */
};

#define TERSAFE_PATCH_COUNT (sizeof(kTersafePatches)/sizeof(kTersafePatches[0]))

/* --- Target module BSS segment global variable offsets, 40 total ---
 * 写入 0 清空内部检测状态标记
 * 基于 native_detection_deep_static.json 中的 BSS 扫描结果
 */
static const uint64_t kTersafeBssOffsets[] = {
    0x47F0, 0x4C28, 0x5800, 0x5848, 0x5888, 0x58B0, 0x58E8, 0x5918,
    0x59A8, 0x5AD8, 0x5B08, 0x5B38, 0x5B60, 0x5B88, 0x62B0, 0x72E0,
    0x7310, 0x7340, 0x7370, 0x73A4, 0x73E8, 0x7410, 0x7448, 0x7478,
    0x74D0, 0x7580, 0x75B0, 0x75E0, 0x7618, 0x7648, 0x7680, 0x76B0,
    0x77E8, 0x7818, 0x78A8, 0x78D0, 0x7960, 0x7988, 0x79C0, 0x9A04,
};
#define TERSAFE_BSS_COUNT (sizeof(kTersafeBssOffsets)/sizeof(kTersafeBssOffsets[0]))

/* Collector-r2 proved the former six UE4 RVAs do not match Build ID
 * 8187ddb9edbc9d5201201ffd7b008df3bfe533db. Keep the fallback table empty
 * until the current binary is re-analysed; writing stale RVAs is worse than
 * skipping this optional layer. */
static const patch_entry_t kUE4Patches[] = {{0, 0, 0, 0}};
#define UE4_PATCH_COUNT 0
#endif

/* ============= Telemetry directories for cleanup ============= */
static const char *kPurgeDirs[] = {
    APP_DATA "/files/ano_tmp",
    APP_DATA "/files/tdm_tmp",
    APP_DATA "/app_crashSight",
    APP_DATA "/files/UE4Game/DeltaForce/DeltaForce/Saved/Config/CrashReportClient",
    APP_DATA "/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack",
    APP_DATA "/files/perfsight",
    NULL
};

/* ============= System property emulation =============
 * Virtualized environment markers → clear or rewrite to reference device profile
 * 属性名和值均来自 kAdaptProps 表
 */
typedef struct {
    const char *key;
    const char *value;  /* NULL = 删除此属性 */
} prop_adapt_t;

static const prop_adapt_t kAdaptProps[] = {
    /* --- Virtualized environment markers: clear --- */
    {"ro.kernel.qemu", NULL},
    {"init.svc.vbox86-setup", NULL},
    {"ro.genymotion.version", NULL},
    {"persist.nox.simulator_version", NULL},
    {"microvirt.memu_version", NULL},
    {"nemud.player_package", NULL},
    {"sys.tencent.init", NULL},
    {"sys.tencent.model", NULL},
    {"net.hostname", NULL},
    {"ro.boot.qemu", NULL},
    {"ro.boot.qemu.avd_name", NULL},
    {"ro.boot.qemu.cpuvulkan.version", NULL},
    {"ro.kernel.android.qemud", NULL},
    {"qemu.hw.mainkeys", NULL},
    {"qemu.sf.lcd_density", NULL},
    /* --- Platform markers: clear --- */
    {"ro.hardware.gralloc", "adreno"},
    {"ro.hardware.egl", "adreno"},
    {"ro.product.base_version", NULL},
    {"ro.product.odm.brand", "samsung"},
    {"ro.product.odm.device", "beyond1q"},
    {"ro.product.odm.manufacturer", "samsung"},
    {"ro.product.odm.model", "SM-G9730"},
    {"ro.product.odm.name", "beyond1qltezc"},
    {"ro.product.odm_dlkm.brand", NULL},
    {"ro.product.odm_dlkm.device", NULL},
    {"ro.product.odm_dlkm.manufacturer", NULL},
    {"ro.product.odm_dlkm.model", NULL},
    {"ro.product.odm_dlkm.name", NULL},
    {"ro.product.product.brand", "samsung"},
    {"ro.product.product.device", "beyond1q"},
    {"ro.product.product.manufacturer", "samsung"},
    {"ro.product.product.model", "SM-G9730"},
    {"ro.product.product.name", "beyond1qltezc"},
    {"ro.product.system.brand", "samsung"},
    {"ro.product.system.device", "beyond1q"},
    {"ro.product.system.manufacturer", "samsung"},
    {"ro.product.system.model", "SM-G9730"},
    {"ro.product.system.name", "beyond1qltezc"},
    {"ro.product.system_ext.brand", "samsung"},
    {"ro.product.system_ext.device", "beyond1q"},
    {"ro.product.system_ext.manufacturer", "samsung"},
    {"ro.product.system_ext.model", "SM-G9730"},
    {"ro.product.system_ext.name", "beyond1qltezc"},
    {"ro.product.vendor.brand", "samsung"},
    {"ro.product.vendor.device", "beyond1q"},
    {"ro.product.vendor.manufacturer", "samsung"},
    {"ro.product.vendor.model", "SM-G9730"},
    {"ro.product.vendor.name", "beyond1qltezc"},
    {"ro.product.ota.host", NULL},
    {"ro.build.characteristics", NULL},
    /* --- Reference device profile (SM-G9730 beyond1q) --- */
    {"ro.product.manufacturer", "samsung"},
    {"ro.product.model", "SM-G9730"},
    {"ro.product.device", "beyond1q"},
    {"ro.product.name", "beyond1qltezc"},
    {"ro.build.product", "beyond1q"},
    {"ro.product.brand", "samsung"},
    {"ro.hardware", "qcom"},
    {"ro.board.platform", "msmnile"},
    {"ro.product.board", "msmnile"},
    {"ro.soc.manufacturer", "QUALCOMM"},
    {"ro.soc.model", "SM8150"},
    {"ro.opengles.version", "196610"},
    {"ro.sf.lcd_density", "420"},
    {"ro.build.fingerprint", "samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"},
    {"ro.build.version.sdk", "30"},
    {"ro.build.version.release", "11"},
    {"ro.build.version.incremental", "G9730ZCS6FULZ"},
    {"ro.build.tags", "release-keys"},
    {"ro.build.type", "user"},
    {"ro.build.user", "dpi"},
    {"ro.build.host", "SWDD6847"},
    {"ro.build.description", "beyond1qltezc-user 11 RP1A.200720.012 G9730ZCS6FULZ release-keys"},
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    {"ro.allow.mock.location", "0"},
    {"persist.sys.usb.config", "adb"},
    {"gsm.version.baseband", "G9730ZCS6FULZ"},
    {"ro.boot.hardware", "qcom"},
    {"ro.boot.bootloader", "unknown"},
    {"ro.bootmode", "unknown"},
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.boot.flash.locked", "1"},
    {NULL, NULL}
};

/* ============= /proc/self/maps 内存文件读写缓存 ============= */
static int  g_mem_fd = -1;
static pid_t g_mem_pid = 0;
static int  g_mem_mode = -1;

static int open_mem(pid_t pid, int mode) {
    if (g_mem_fd >= 0 && g_mem_pid == pid && g_mem_mode == mode)
        return g_mem_fd;
    if (g_mem_fd >= 0) { close(g_mem_fd); g_mem_fd = -1; }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    g_mem_fd = open(path, mode);
    if (g_mem_fd >= 0) { g_mem_pid = pid; g_mem_mode = mode; }
    return g_mem_fd;
}

static int mem_read32(pid_t pid, uint64_t addr, uint32_t *out) {
    int fd = open_mem(pid, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) != (off_t)addr) return -1;
    if (read(fd, out, 4) != 4) return -1;
    return 0;
}

static int mem_write32(pid_t pid, uint64_t addr, uint32_t val) {
    int fd = open_mem(pid, O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) != (off_t)addr) return -1;
    if (write(fd, &val, 4) != 4) return -1;
    return 0;
}

/* 安全写入: 随机延时 + 回读校验 + 重试 */
static int safe_write32(pid_t pid, uint64_t addr, uint32_t val, int max_retries) {
    for (int i = 0; i < max_retries; i++) {
        usleep(1000 + (rand() % 10000));
        if (mem_write32(pid, addr, val) == 0) {
            usleep(1000 + (rand() % 10000));
            uint32_t rb = 0;
            if (mem_read32(pid, addr, &rb) == 0 && rb == val)
                return 0;
        }
        usleep(10000 + (rand() % 50000));
    }
    return -1;
}

/* 写时校验: patch 前先读原始指令，避免写到错误偏移 */
static int safe_verify_and_write(pid_t pid, uint64_t addr, const patch_entry_t *patch) {
    JUNK_INSN();
    if (!patch) return -1;
    uint32_t before = 0;
    if (mem_read32(pid, addr, &before) != 0) return -1;
    if (before == patch->value) return 0;  /* 已在目标值，跳过 */
    if (patch->has_expected && before != patch->expected) {
        WARN("[verify] 0x%llx original=0x%08x expected=0x%08x, skip",
             (unsigned long long)addr, before, patch->expected);
        return -1;
    }
    return safe_write32(pid, addr, patch->value, 3);
}

static const patch_entry_t *find_validated_patch(uint64_t offset) {
    if (!g_dyn_loaded) return NULL;
    for (size_t i = 0; i < DYN_TERSAFE_COUNT; i++) {
        if (DYN_TERSAFE_PATCHES[i].offset == offset)
            return &DYN_TERSAFE_PATCHES[i];
    }
    return NULL;
}

static int preflight_code_table(pid_t pid, uint64_t base,
                                const patch_entry_t *entries, size_t count,
                                const char *name) {
    size_t accepted = 0;
    size_t rejected = 0;
    for (size_t i = 0; i < count; i++) {
        uint32_t current = 0;
        int readable = mem_read32(pid, base + entries[i].offset, &current) == 0;
        if (!entries[i].has_expected || !readable
            || (current != entries[i].expected && current != entries[i].value)) {
            ERR("[preflight] %s[%zu] rejected off=0x%llx readable=%d current=0x%08x expected=0x%08x patch=0x%08x",
                name, i, (unsigned long long)entries[i].offset, readable,
                current, entries[i].expected, entries[i].value);
            rejected++;
        } else {
            accepted++;
        }
    }
    if (rejected != 0) {
        ERR("[preflight] %s table rejected: accepted=%zu rejected=%zu total=%zu",
            name, accepted, rejected, count);
        return 0;
    }
    OK("[preflight] %s table accepted: %zu/%zu", name, count, count);
    return 1;
}

static int preflight_bss_table(pid_t pid, uint64_t bss_base,
                               uint64_t module_limit) {
    for (size_t i = 0; i < DYN_BSS_COUNT; i++) {
        uint64_t addr = bss_base + DYN_BSS_OFFSETS[i];
        uint32_t current = 0;
        if (DYN_BSS_OFFSETS[i] > 0xC00000 || addr >= module_limit
            || mem_read32(pid, addr, &current) != 0) {
            ERR("[preflight] bss[%zu] unreadable/out-of-range off=0x%llx",
                i, (unsigned long long)DYN_BSS_OFFSETS[i]);
            return 0;
        }
    }
    OK("[preflight] bss table readable: %zu/%zu", DYN_BSS_COUNT, DYN_BSS_COUNT);
    return 1;
}

/* ============= /proc/[pid]/maps 解析 ============= */
static uint64_t get_module_base(pid_t pid, const char *module_spec) {
    char buf[128], line[1024], path[64];
    snprintf(buf, sizeof(buf), "%s", module_spec);
    char *lib = strtok(buf, ":");
    char *seg = strtok(NULL, ":");
    int bss_mode = (seg && strcmp(seg, "bss") == 0);

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t base = 0;
    int found_lib = 0;
    while (fgets(line, sizeof(line), f)) {
        if (found_lib) {
            if (strstr(line, "[anon:.bss]")) {
                base = strtoull(line, NULL, 16);
                break;
            }
            /* 遇到另一个 .so 路径说明已跨过目标库，停止搜索 */
            if (strstr(line, ".so") && !strstr(line, lib)) {
                break;
            }
            /* 继续向下搜索，不重置 found_lib */
        } else if (strstr(line, lib)) {
            if (!bss_mode) { base = strtoull(line, NULL, 16); break; }
            found_lib = 1;
        }
    }
    fclose(f);
    return base;
}

/* 轮询等待 so 加载, 渐进退避 100ms→2000ms, timeout_ms 超时返回 0 */
static uint64_t wait_for_module(pid_t pid, const char *mod, int timeout_ms) {
    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    unsigned delay = BACKOFF_BASE_MS;
    for (;;) {
        uint64_t b = get_module_base(pid, mod);
        if (b) return b;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        long elapsed = (long)((ts_now.tv_sec - ts_start.tv_sec) * 1000 +
                              (ts_now.tv_nsec - ts_start.tv_nsec) / 1000000);
        if (elapsed >= timeout_ms) return 0;
        usleep(delay * 1000);
        delay = delay < BACKOFF_MAX_MS ? delay * 2 : BACKOFF_MAX_MS;
    }
}

/* ============= 进程查找: /proc 遍历 + cmdline 匹配 ============= */
static pid_t get_pid_by_name(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *ent;
    pid_t r = 0;
    while ((ent = readdir(d)) != NULL) {
        size_t pid_len = strlen(ent->d_name);
        if (pid_len == 0 || pid_len > 20 || strspn(ent->d_name, "0123456789") != pid_len)
            continue;
        char p[64];
        if (snprintf(p, sizeof(p), "/proc/%s/cmdline", ent->d_name) >= (int)sizeof(p))
            continue;
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {0};
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0 && strstr(buf, name)) { r = (pid_t)atoi(ent->d_name); break; }
    }
    closedir(d);
    return r;
}

static int target_is_running(void) {
    return get_pid_by_name(TARGET_PKG) != 0;
}

/* ============= 文件系统递归删除 — 含路径安全校验 ============= */
static int rm_recursive(const char *path) {
    /* 安全网: 只允许删 /data/data/ 和 /data/local/tmp/ 下的文件 */
    if (!path || (strncmp(path, "/data/data/", 11) != 0 &&
                  strncmp(path, "/data/local/tmp/", 16) != 0 &&
                  strncmp(path, "/sdcard/", 8) != 0)) {
        return -1;
    }
    struct stat st;
    if (lstat(path, &st) != 0) return (errno == ENOENT) ? 0 : -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
                char full[4096];
                snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
                rm_recursive(full);
            }
            closedir(d);
        }
        rmdir(path);
        return 0;
    }
    unlink(path);
    return 0;
}

/* ============= Shell 命令执行 ============= */
static int run_cmd(const char *argv[]) {
    pid_t p = fork();
    if (p == -1) return -1;  /* fork 失败 */
    if (p == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); close(dn); }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run_shell_best_effort(const char *cmd) {
    int rc = system(cmd);
    if (rc != 0) WARN("shell command failed rc=%d: %.120s", rc, cmd);
    return rc;
}

static int apply_identity_namespace(pid_t pid) {
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    const char *argv[] = {
        "/system/bin/sh",
        "/data/local/tmp/system_identity_overlay.sh",
        "apply-pid",
        pid_str,
        NULL
    };
    int rc = run_cmd(argv);
    if (rc == 0)
        OK("identity overlay applied in game mount namespace pid=%d", pid);
    else
        WARN("identity overlay missing in game mount namespace pid=%d rc=%d; verifier will report exposed nodes", pid, rc);
    return rc;
}

static int write_all_fd(int fd, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* ============= 系统属性适配 ============= */

/* 查找 resetprop 二进制 (Magisk 路径不在默认 PATH 里) */
static const char *find_resetprop(void) {
    static char rp[128] = {0};
    if (rp[0]) return rp;
    static const char *cands[] = {
        "/data/local/tmp/resetprop",          /* standalone 手动部署 */
        "/system/bin/resetprop",
        "/data/adb/magisk/resetprop",
        "/data/adb/ksu/bin/resetprop",
        "/data/adb/magisk32/resetprop",
        "/sbin/.magisk/mirror/system/bin/resetprop",
        "/sbin/resetprop",
        NULL
    };
    struct stat st;
    for (int i = 0; cands[i]; i++) {
        if (stat(cands[i], &st) == 0 && S_ISREG(st.st_mode)) {
            snprintf(rp, sizeof(rp), "%s", cands[i]);
            return rp;
        }
    }
    return NULL;  /* resetprop 不可用 */
}

static void adapt_properties(void) {
    const char *rp = find_resetprop();
    if (!rp) WARN("未找到 resetprop — ro.* 只读属性无法修改，libforgehook hook 兜底");

    int ok = 0, fail = 0;
    for (const prop_adapt_t *s = kAdaptProps; s->key; s++) {
        char cmd[640];
        if (s->value) {
            if (rp)
                snprintf(cmd, sizeof(cmd),
                    "%s '%s' '%s' 2>/dev/null || setprop '%s' '%s' 2>/dev/null",
                    rp, s->key, s->value, s->key, s->value);
            else
                snprintf(cmd, sizeof(cmd),
                    "setprop '%s' '%s' 2>/dev/null", s->key, s->value);
        } else {
            if (rp)
                snprintf(cmd, sizeof(cmd),
                    "%s --delete '%s' 2>/dev/null || setprop '%s' '' 2>/dev/null",
                    rp, s->key, s->key);
            else
                snprintf(cmd, sizeof(cmd),
                    "setprop '%s' '' 2>/dev/null", s->key);
        }
        if (system(cmd) == 0) ok++; else fail++;
    }
    OK("Property emulation complete — resetprop=%s ok=%d fail=%d",
       rp ? rp : "N/A", ok, fail);
}

/* ============= Virtualization trace file cleanup ============= */
static void clean_virt_traces(void) {
    /* --- 可删除的文件系统路径 --- */
    static const char *traces[] = {
        "/system/bin/qemud", "/system/bin/qemu-props",
        "/system/bin/androVM-prop", "/system/bin/microvirt-prop",
        "/system/bin/nox-prop", "/system/bin/ttVM-prop",
        "/system/bin/droid4x-prop", "/system/lib/libdroid4x.so",
        "/system/lib/vbox", "/system/lib/ko",
        "/sdcard/Tencent/GameDetect/.detect",
        "/sdcard/Tencent/GameSecurity/violate.log",
        NULL
    };
    int cleaned = 0;
    for (const char **p = traces; *p; p++) {
        if (rm_recursive(*p) == 0) cleaned++;
    }
    OK("虚拟化痕迹清理: %d 项", cleaned);

    /* --- sysfs 节点 (不可删除，由 libforgehook.so 的 HIDDEN 数组拦截访问) ---
     * /sys/class/misc/qemu, /sys/class/misc/vbox, /sys/class/misc/vhost
     * /sys/bus/virtio — 内核虚拟文件系统，文件操作返回 ENOENT 由 hook 库处理
     */
    WARN("sysfs 隐藏依赖 libforgehook.so: /sys/class/misc/{qemu,vbox,vhost}, /sys/bus/virtio");
}

/* ============= Telemetry file batch cleanup ============= */
/* 使用 truncate(0) 代替 unlink：保留 inode/目录项，仅清空内容。
 * unlink 触发游戏第三方插件检测（可能因 inotify/文件存在性校验）；
 * truncate 保留文件但令游戏 SDK 读到空数据，等效清空指纹。 */
static int safe_trunc(const char *path) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int clean_all_ac_files(void) {
    static const char * const kACFiles[] = {
        APP_DATA "/shared_prefs/GCloudCoreSP.xml",
        APP_DATA "/shared_prefs/tdm.xml",
        APP_DATA "/shared_prefs/tgpa.xml",
        APP_DATA "/shared_prefs/qm_global_sp.xml",
        APP_DATA "/shared_prefs/ACE-MSDK.xml",
        APP_DATA "/shared_prefs/TGPA_ShieldSDK_Data.xml",
        APP_DATA "/shared_prefs/mmkvlite_log_app_state.mmkv",
        APP_DATA "/files/GPMSDK.mmap3",
        APP_DATA "/files/tdm_track.dat",
        APP_DATA "/files/qimei_deviceId",
        APP_DATA "/databases/analytics.db",
        APP_DATA "/databases/tencent_analytics.db",
        NULL
    };
    int count = 0;
    for (int i = 0; kACFiles[i]; i++)
        count += safe_trunc(kACFiles[i]);
    OK("[clean_ac] truncated %d AC files", count);
    return count;
}

/* ============= 目录重建 + SELinux 上下文修复 ============= */
static void restore_dirs(void) {
    for (int i = 0; kPurgeDirs[i]; i++) {
        struct stat st;
        if (stat(kPurgeDirs[i], &st) != 0) mkdir(kPurgeDirs[i], 0771);
    }
    const char *argv[] = {"/system/bin/restorecon", "-R", (char*)APP_DATA, NULL};
    run_cmd(argv);
}

/* ============= Process name normalization (prctl) ============= */
static void disguise_self(void) {
    prctl(PR_SET_NAME, "[kworker/0:1-mm]", 0, 0, 0);
}

/* ============= 保护 ADB / 开发者模式 ============= */
static void protect_devmode(void) {
    run_shell_best_effort("settings put global adb_enabled 1 2>/dev/null");
    run_shell_best_effort("settings put global development_settings_enabled 1 2>/dev/null");
    run_shell_best_effort("setprop persist.sys.usb.config adb 2>/dev/null");
    run_shell_best_effort("setprop persist.sys.vold_app_data_isolation_enabled 0 2>/dev/null");
}

/* ============= iptables 清理 =============
 * 移除此前版本遗留的阻断规则，避免游戏无法联网。
 * Telemetry data interception is handled in-process by libforgehook.so null_redir().
 */
static void block_tdm_reporting(void) {
    char uid_buf[32] = {0};
    FILE *fp = popen("dumpsys package com.tencent.tmgp.dfm 2>/dev/null | grep -o 'userId=[0-9]*' | head -1 | sed 's/userId=//'", "r");
    if (fp) {
        if (fgets(uid_buf, sizeof(uid_buf), fp))
            uid_buf[strcspn(uid_buf, "\n")] = 0;
        pclose(fp);
    }

    /* 清理旧版本残留的阻断规则（DROP ALL / string match），防止游戏断网 */
    char cmd[512];
    if (uid_buf[0]) {
        snprintf(cmd, sizeof(cmd),
            "iptables -D OUTPUT -m owner --uid-owner %s -j DROP 2>/dev/null; "
            "iptables -D OUTPUT -m owner --uid-owner %s -p udp --dport 53 -j ACCEPT 2>/dev/null; "
            "iptables -D OUTPUT -m owner --uid-owner %s -p tcp --dport 443 -j ACCEPT 2>/dev/null",
            uid_buf, uid_buf, uid_buf);
        run_shell_best_effort(cmd);
    }
    /* string 匹配规则清理 */
    static const char *OLD_STRINGS[] = {
        "tdm.qq.com", "crashsight.qq.com", "gcloud.tencent.com",
        "report.qq.com", "stat.qq.com", "cloud.tencent.com",
        "gamelobby.qq.com", "igame.qq.com", NULL
    };
    for (const char **s = OLD_STRINGS; *s; s++) {
        snprintf(cmd, sizeof(cmd),
            "iptables -D OUTPUT -m string --algo bm --string '%s' -j DROP 2>/dev/null",
            *s);
        run_shell_best_effort(cmd);
    }
    OK("iptables 旧规则已清理，游戏网络不受影响 (uid=%s)", uid_buf[0] ? uid_buf : "N/A");
}

/* Mapping normalization is process-local.  The external controller must not
 * attempt to edit kernel-generated maps text or mapped ELF headers. */
static void hide_injection_from_maps(pid_t pid) {
    (void)pid;
    /* /proc/PID/maps is kernel-generated text, not writable process memory.
     * The old implementation corrupted the first 16 bytes of the mapped ELF.
     * Mapping normalization now lives in libforgehook constructor(104), with
     * filtered maps/smaps reads as the second layer. */
    OK("maps concealment delegated to in-process mapping normalization");
}

/* ============= 杀死可疑检测进程 ============= */
static void kill_suspicious_procs(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *ent;
    while ((ent = readdir(proc)) != NULL) {
        pid_t pid = (pid_t)strtoul(ent->d_name, NULL, 10);
        if (pid <= 0) continue;
        char mp[64];
        snprintf(mp, sizeof(mp), "/proc/%d/maps", pid);
        FILE *fp = fopen(mp, "r");
        if (!fp) continue;
        char line[1024];
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "lib5.so") || strstr(line, "libsandbox.so") ||
                strstr(line, "libdetect.so") || strstr(line, "libemulator_check.so")) {
                found = 1; break;
            }
        }
        fclose(fp);
        if (found) { kill(pid, SIGKILL); }
    }
    closedir(proc);
}

/* ============= 游戏进程启停 ============= */
static void stop_game(void) {
    char buf[256];
    snprintf(buf, sizeof(buf), "am force-stop %s 2>/dev/null", TARGET_PKG);
    run_shell_best_effort(buf);
    snprintf(buf, sizeof(buf), "killall -9 %s 2>/dev/null", TARGET_PKG);
    run_shell_best_effort(buf);
}

static void start_game(void) {
    char buf[1024];

    /* Step 1: 裸启游戏
     * Android 8+ linker namespace 隔离: /data/local/tmp/ 不在 app namespace,
     * wrap.xxx LD_PRELOAD 和 setprop 均无效, libforgehook.so 通过 hijack 或
     * ptrace 注入加载 */
    snprintf(buf, sizeof(buf),
        "am start -n %s/com.epicgames.ue4.SplashActivity 2>/dev/null",
        TARGET_PKG);
    run_shell_best_effort(buf);
    OK("游戏已启动，等待进程出现后注入...");
}

/*
 * stage_hook_so: 把 libforgehook.so 复制到游戏的 native lib 目录
 * 绕过 Android 8+ linker namespace 隔离:
 *   dlopen("/data/local/tmp/...") → 失败（不在 app namespace）
 *   dlopen("/data/app/.../lib/arm64/...") → 成功（已在 app namespace）
 */
static void stage_hook_so(pid_t pid, char *out_path, size_t out_sz) {
    strncpy(out_path, C_hook_so, out_sz - 1);
    out_path[out_sz - 1] = '\0';

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return;

    char line[1024], dst[768] = {0};
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "/data/app/");
        if (!p) continue;
        char *lib = strstr(p, "/lib/arm64/");
        if (!lib) continue;
        size_t dir_len = (size_t)(lib - p) + strlen("/lib/arm64/");
        if (dir_len + 20 > sizeof(dst)) continue;
        memcpy(dst, p, dir_len);
        dst[dir_len] = '\0';
        size_t dl = strlen(dst);
        while (dl > 0 && (dst[dl-1]=='\n'||dst[dl-1]==' '||dst[dl-1]=='\t')) dst[--dl]='\0';
        strncat(dst, "libforgehook.so", sizeof(dst) - strlen(dst) - 1);
        break;
    }
    fclose(f);
    if (!dst[0]) return;

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "cp /data/local/tmp/libforgehook.so '%s' && chmod 755 '%s' && "
        "(restorecon '%s' 2>/dev/null || true)",
        dst, dst, dst);
    if (system(cmd) == 0) {
        strncpy(out_path, dst, out_sz - 1);
        out_path[out_sz - 1] = '\0';
        OK("hook 库暂存到 app lib 目录 (绕 namespace): %.80s", out_path);
    } else {
        WARN("hook 库暂存失败，保持原路径");
    }
}

/* [v7.0 Fix] inject_hook — 用 fork+execv 替代 system() 字符串拼接
 * 原版: system("/data/local/tmp/injector %d '%s'", pid, hook_path)
 * 风险: hook_path 含特殊字符时 shell 解析错误或注入。
 * 修复: execv 直接传参数数组，路径白名单验证。*/
static int inject_hook(pid_t pid) {
    JUNK_INSN();
    char hook_path[768];
    stage_hook_so(pid, hook_path, sizeof(hook_path));
    /* 路径白名单：只允许 /data/app/ 和 /data/local/tmp/ */
    if (strncmp(hook_path, "/data/app/", 10) != 0 &&
        strncmp(hook_path, "/data/local/tmp/", 16) != 0) {
        ERR("inject_hook: 拒绝不可信路径: %.80s", hook_path);
        return -1;
    }
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    const char *const argv[] = { C_injector_path, pid_str, hook_path, NULL };
    pid_t child = fork();
    if (child < 0) { ERR("fork failed: %s", strerror(errno)); return -1; }
    if (child == 0) {
        int log_fd = open(FORGE_LOG, O_WRONLY|O_CREAT|O_APPEND, 0600);
        if (log_fd >= 0) { dup2(log_fd, 1); dup2(log_fd, 2); close(log_fd); }
        execv(argv[0], (char *const *)argv);
        ERR("execv injector failed: %s", strerror(errno));
        _exit(127);
    }
    /* 带 10s 超时等待子进程 */
    int status = 0;
    time_t deadline = time(NULL) + 10;
    while (1) {
        pid_t w = waitpid(child, &status, WNOHANG);
        if (w == child) break;
        if (w < 0 && errno != EINTR) { kill(child, SIGKILL); waitpid(child, NULL, 0); return -1; }
        if (time(NULL) > deadline) { kill(child, SIGKILL); waitpid(child, NULL, 0);
            ERR("injector timed out"); return -1; }
        usleep(50000);
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ============= 核心: 内存补丁执行 ============= */
static int patch_game_process(void) {
    JUNK_INSN();
    pid_t pid = 0;
    for (int i = 0; i < 600; i++) {
        pid = get_pid_by_name(TARGET_PKG);
        if (pid) break;
        usleep(100000);
    }
    if (!pid) { WARN("未找到游戏进程"); return -1; }
    OK("游戏 PID: %d", pid);

    if (!g_dyn_loaded) {
        ERR("validated patch table not loaded: %s", FORGE_PATCH_JSON);
        return -2;
    }

    int total_ok = 0, total_fail = 0;
    int tersafe_ok = 0, tersafe_fail = 0;
    int bss_ok = 0, bss_fail = 0;
    int ue4_ok = 0, ue4_fail = 0;

    /* 0. 等待模块后再做 fail-closed Build ID 校验。 */
    uint64_t ts_base = wait_for_module(pid, C_tersafe, 30000);
    if (ts_base == 0) {
        ERR("libtersafe.so 未加载 — ABORT，拒绝在不存在模块上写内存");
        return -1;
    }
    if (verify_tersafe_version(pid) == 0) {
        WARN("版本校验失败，跳过所有内存 patch");
        return -2;
    }

    /* 验证基址有效性: 读已知偏移确认可读 */
    uint32_t sanity = 0;
    if (mem_read32(pid, ts_base + 0x100, &sanity) != 0) {
        ERR("libtersafe.so 基址读取失败 — abort patching");
        return -1;
    }
    if (sanity == 0 || sanity == 0xFFFFFFFF) {
        ERR("libtersafe.so 基址无效 sanity=0x%x — abort", sanity);
        return -1;
    }
    OK("libtersafe.so base=0x%lx", (unsigned long)ts_base);

    uint64_t bss_base = get_module_base(pid, "libtersafe.so:bss");
    uint64_t bss_limit = ts_base + 0xC00000;
    if (!preflight_code_table(pid, ts_base, DYN_TERSAFE_PATCHES,
            DYN_TERSAFE_COUNT, "tersafe")
        || bss_base == 0
        || !preflight_bss_table(pid, bss_base, bss_limit)) {
        ERR("patch transaction preflight failed; no target writes performed");
        return -2;
    }

    /* 2. tersafe 代码补丁 75 处 (verify-before-patch) */
    for (size_t i = 0; i < DYN_TERSAFE_COUNT; i++) {
        uint64_t addr = ts_base + DYN_TERSAFE_PATCHES[i].offset;
        if (safe_verify_and_write(pid, addr, &DYN_TERSAFE_PATCHES[i]) == 0) tersafe_ok++;
        else tersafe_fail++;
    }
    OK("tersafe code: %d ok / %d fail", tersafe_ok, tersafe_fail);
    total_ok += tersafe_ok; total_fail += tersafe_fail;

    /* 3. tersafe BSS 段清零 */
    if (bss_base > 0) {
        /* 3a. Only clear the explicit JSON offsets.  There is intentionally no
         * low-value sweep: guessing counters can corrupt unrelated state. */
        for (size_t i = 0; i < DYN_BSS_COUNT; i++) {
            uint64_t addr = bss_base + DYN_BSS_OFFSETS[i];
            if (DYN_BSS_OFFSETS[i] > 0xC00000 || addr >= bss_limit) {
                bss_fail++; continue;
            }
            if (safe_write32(pid, addr, 0, 3) == 0) bss_ok++;
            else bss_fail++;
        }

        OK("tersafe bss: %d ok / %d fail", bss_ok, bss_fail);
        total_ok += bss_ok; total_fail += bss_fail;
    } else {
        WARN("tersafe BSS 段未找到 (跳过)");
    }

    /* 4. UE4 table is optional and currently quarantined for this Build ID. */
    uint64_t ue4_base = DYN_UE4_COUNT ? wait_for_module(pid, C_ue4, 20000) : 0;
    if (ue4_base && DYN_UE4_COUNT
        && verify_module_version(pid, "libUE4.so", g_dyn_table.ue4_build_id)) {
        if (!preflight_code_table(pid, ue4_base, DYN_UE4_PATCHES,
                DYN_UE4_COUNT, "ue4")) {
            ERR("UE4 transaction preflight failed");
            return -2;
        }
        usleep(500000);
        for (size_t i = 0; i < DYN_UE4_COUNT; i++) {
            uint64_t addr = ue4_base + DYN_UE4_PATCHES[i].offset;
            if (safe_verify_and_write(pid, addr, &DYN_UE4_PATCHES[i]) == 0) ue4_ok++;
            else ue4_fail++;
        }
        OK("UE4: %d ok / %d fail", ue4_ok, ue4_fail);
        total_ok += ue4_ok; total_fail += ue4_fail;
    } else if (DYN_UE4_COUNT) {
        WARN("libUE4.so missing or Build ID rejected (skip engine table)");
    } else {
        WARN("UE4 patch table quarantined for Build ID 8187ddb9edbc9d5201201ffd7b008df3bfe533db");
    }

    OK("内存调整完成: %d ok / %d fail", total_ok, total_fail);
    if (total_fail > WRITE_FAIL_ABORT_THRESHOLD) {
        ERR("patch 失败数 (%d) 超过阈值 (%d) — abort",
            total_fail, WRITE_FAIL_ABORT_THRESHOLD);
        return -1;
    }

    /* 立即验证 检测链 — tersafe 可能在补丁后几十毫秒内恢复 */
    if (ts_base) {
        usleep(50000); /* 等 50ms 让 tersafe 的恢复线程跑完 */
        int reverted = 0;
        for (size_t i = 0; i < DYN_TERSAFE_COUNT; i++) {
            uint32_t cur = 0;
            if (mem_read32(pid, ts_base + DYN_TERSAFE_PATCHES[i].offset, &cur) == 0
                && cur != DYN_TERSAFE_PATCHES[i].value) {
                if (safe_verify_and_write(pid,
                        ts_base + DYN_TERSAFE_PATCHES[i].offset,
                        &DYN_TERSAFE_PATCHES[i]) == 0)
                    reverted++;
            }
        }
        if (reverted > 0)
            WARN("validated code table: %d entries reverted and restored", reverted);
    }
    return 0;
}

/* ============= 全局执行流程 ============= */
static volatile sig_atomic_t g_stop = 0;
static void sig_handler(int sig) { (void)sig; g_stop = 1; }

/* ================================================================
 * v8.7 深层设备环境重建 — 整合神念/时间刺客技术
 *
 * 云机伪装真手机的7个层次：
 * L0: IP/ASN      — WireGuard 出口 (见 runner/setup_network.sh)
 * L1: 内核级      — mount --bind /sys/devices/soc0/serial_number
 * L2: 全局属性    — resetprop IMEI/Serial
 * L3: 身份文件    — OAID/VAID 文件替换
 * L4: SSAID       — settings_ssaid.xml 深度修改
 * L5: DFM 指纹    — 清理 TDM/QIMEI/登录记录
 * L6: 进程运行时  — TerSafe patch + LD_PRELOAD (已有)
 * ================================================================ */
#define SERIAL_KERN_PATH "/sys/devices/soc0/serial_number"
#define SERIAL_BIND_TMP  "/data/local/tmp/.sn_bind"
#define OAID_PATH        "/data/system/oaid_persistence_0"
#define VAID_PATH        "/data/system/vaid_persistence_platform"
#define SSAID_XML        "/data/system/users/0/settings_ssaid.xml"

/* /dev/urandom 生成 len 位十六进制字符串 */
static void hwid_rand_hex(char *buf, size_t len) {
    unsigned char raw[64];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { snprintf(buf, len + 1, "%0*d", (int)len, 0); return; }
    size_t need = (len + 1) / 2;
    if (need > sizeof(raw)) need = sizeof(raw);
    if (read(fd, raw, need) <= 0) {/* partial ok */}
    close(fd);
    for (size_t i = 0; i < len; i++)
        snprintf(buf + i, 3, "%02x", (unsigned)(raw[i / 2]));
    buf[len] = '\0';
}

/* Samsung 序列号格式: R 开头共 11 位大写字母数字，如 R58M74JXMWP */
static void hwid_samsung_serial(char *buf, size_t sz) {
    static const char *ch = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    unsigned char raw[12];
    if (sz < 12) { if (sz) buf[0] = '\0'; return; }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { if (read(fd, raw, sizeof(raw)) <= 0) {/*ok*/} close(fd); }
    buf[0] = 'R';
    for (int i = 1; i < 11; i++) buf[i] = ch[raw[i] % 34];
    buf[11] = '\0';
}

/* Luhn 校验位 — 计算 14 位数字的第 15 位校验位 */
static int luhn_check_digit(const char *d14) {
    int sum = 0;
    for (int i = 0; i < 14; i++) {
        int v = d14[13 - i] - '0';
        if (i % 2 == 0) { v *= 2; if (v > 9) v -= 9; }
        sum += v;
    }
    return (10 - sum % 10) % 10;
}

/* 生成合法 IMEI: TAC=35982510 (Samsung SM-G9730) + 随机6位 + Luhn */
static void hwid_gen_imei(char *buf) {
    unsigned char raw[3];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { if (read(fd, raw, 3) <= 0) {/*ok*/} close(fd); }
    snprintf(buf, 16, "35982510%02d%02d%02d",
             (int)(raw[0] % 100), (int)(raw[1] % 100), (int)(raw[2] % 100));
    buf[14] = '0' + luhn_check_digit(buf);
    buf[15] = '\0';
}

/* L1: mount --bind 内核 serial_number 节点
 * 不同 SoC 路径不同，依次尝试 */
static void spoof_serial_bind(void) {
    static const char * const sn_paths[] = {
        "/sys/devices/soc0/serial_number",
        "/sys/class/android_usb/android0/iSerial",
        "/sys/devices/platform/soc/soc:usb-phy/serial_number",
        "/proc/cpuinfo",   /* 作为只读 bind 源，不挂载此，仅做探测 */
        NULL
    };
    const char *target = NULL;
    for (int i = 0; sn_paths[i]; i++) {
        if (i == 3) break;  /* /proc/cpuinfo 仅探测用，不 bind */
        if (access(sn_paths[i], F_OK) == 0) { target = sn_paths[i]; break; }
    }
    if (!target) { WARN("[L1] serial_number sysfs 路径未找到，跳过 bind"); return; }

    char serial[16]; hwid_samsung_serial(serial, sizeof(serial));
    int fd = open(SERIAL_BIND_TMP, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { WARN("[L1] serial tmp: %s", strerror(errno)); return; }
    if (write_all_fd(fd, serial, strlen(serial)) != 0) {
        WARN("[L1] serial tmp write: %s", strerror(errno));
        close(fd);
        return;
    }
    close(fd);
    umount2(target, MNT_DETACH);
    if (mount(SERIAL_BIND_TMP, target, NULL, MS_BIND | MS_RDONLY, NULL) == 0)
        OK("[L1] serial bind %s → %s", target, serial);
    else
        WARN("[L1] serial bind %s failed: %s", target, strerror(errno));
}

/* L2: resetprop 全局覆写 IMEI 与序列号
 * 优先 Magisk/KernelSU 内置，回退到用户手动部署的 standalone resetprop
 * 若均不可用则保持 fail-closed，由进程 Hook 兜底，不持久化修改系统分区。 */
static void resetprop_identity(void) {
    static const char * const rp_locs[] = {
        "/system/bin/resetprop",
        "/data/adb/magisk/resetprop",
        "/data/adb/ksu/bin/resetprop",
        "/data/local/tmp/resetprop",   /* standalone 手动部署路径 */
        "/sbin/resetprop",             /* 某些旧版 Magisk */
        NULL
    };
    const char *rp = NULL;
    for (int i = 0; rp_locs[i]; i++)
        if (access(rp_locs[i], X_OK) == 0) { rp = rp_locs[i]; break; }
    if (!rp) {
        WARN("[L2] resetprop not found; skip global identity mutation, process hook only");
        return;
    }

    char imei[16], imei2[16], serial[16];
    hwid_gen_imei(imei); hwid_gen_imei(imei2);
    hwid_samsung_serial(serial, sizeof(serial));

    char cmd[320];
#define RP(k, v) do { snprintf(cmd,sizeof(cmd),"%s %s %s 2>/dev/null",rp,(k),(v)); run_shell_best_effort(cmd); } while(0)
    RP("ro.serialno",        serial);
    RP("ro.boot.serialno",   serial);
    RP("sys.serialno",       serial);
    RP("ril.imei",           imei);
    RP("ril.imei1",          imei);
    RP("ril.imei2",          imei2);
    RP("gsm.imei",           imei);
    RP("persist.radio.imei", imei);
    RP("ro.ril.miui.imei0",  imei);
#undef RP
    /* 循环覆盖所有名称含 imei 的属性 */
    snprintf(cmd, sizeof(cmd),
        "for k in $(getprop | sed -n 's/\\[\\([^]]*imei[^]]*\\)\\].*/\\1/Ip'); do "
        "  v=$(getprop \"$k\"); "
        "  [ \"${#v}\" -ge 14 ] && %s \"$k\" '%s' 2>/dev/null; "
        "done", rp, imei);
    run_shell_best_effort(cmd);
    OK("[L2] resetprop done (IMEI=%s serial=%s)", imei, serial);
}

static void spoof_oaid_vaid(void) {
    char hex[17]; int fd;
    hwid_rand_hex(hex, 16);
    fd = open(OAID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (write_all_fd(fd, hex, 16) == 0) OK("[L3] OAID → %s", hex);
        else WARN("[L3] OAID short write: %s", strerror(errno));
        close(fd);
    }
    else WARN("[L3] OAID write: %s", strerror(errno));

    hwid_rand_hex(hex, 16);
    fd = open(VAID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (write_all_fd(fd, hex, 16) == 0) OK("[L3] VAID → %s", hex);
        else WARN("[L3] VAID short write: %s", strerror(errno));
        close(fd);
    }
    else WARN("[L3] VAID write: %s", strerror(errno));
}

/* L4: settings_ssaid.xml 深度修改 (abx2xml → sed → xml2abx)
 * SSAID 是游戏用于绑定设备的最持久标识之一 */
static void spoof_ssaid(void) {
    /* Android 不同版本 SSAID XML 路径不同 */
    static const char * const ssaid_paths[] = {
        "/data/system/users/0/settings_ssaid.xml",
        "/data/system/0/settings_ssaid.xml",
        "/data/system/users/0/settings.xml",
        NULL
    };
    const char *xml = NULL;
    for (int i = 0; ssaid_paths[i]; i++)
        if (access(ssaid_paths[i], F_OK) == 0) { xml = ssaid_paths[i]; break; }
    if (!xml) { WARN("[L4] settings_ssaid.xml 未找到，跳过"); return; }

    /* 确认工具可用 */
    const char *abx2xml =
        access("/system/bin/abx2xml", X_OK) == 0  ? "/system/bin/abx2xml" :
        access("/system/xbin/abx2xml", X_OK) == 0 ? "/system/xbin/abx2xml" : NULL;
    if (!abx2xml) { WARN("[L4] abx2xml not available, skip SSAID deep mod"); return; }

    char dfm_hex[17]; hwid_rand_hex(dfm_hex, 16);
    char cmd[768];
    snprintf(cmd, sizeof(cmd),
        "%s -i '%s' 2>/dev/null && "
        "OLD_UK=$(grep -oP '(?<=\")[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}(?=\")' '%s' | head -1) && "
        "NEW_UK=$(cat /proc/sys/kernel/random/uuid) && "
        "[ -n \"$OLD_UK\" ] && sed -i \"s|$OLD_UK|$NEW_UK|g\" '%s' 2>/dev/null; "
        "OLD_AID=$(grep -oP '(?<=value=\")[0-9a-f]{16}(?=\")' '%s' | head -1) && "
        "[ -n \"$OLD_AID\" ] && sed -i \"s|$OLD_AID|%s|g\" '%s' 2>/dev/null; "
        "xml2abx -i '%s' 2>/dev/null",
        abx2xml, xml, xml, xml, xml, dfm_hex, xml, xml);
    int rc = system(cmd);
    if (rc == 0) OK("[L4] SSAID rotated @ %s (DFM=%s)", xml, dfm_hex);
    else WARN("[L4] SSAID mod rc=%d @ %s", rc, xml);
}

/* L5: DFM 游戏指纹缓存彻底清理
 * 这些文件存储设备指纹与登录历史，清理后游戏视为全新设备 */
static void clean_dfm_fingerprints(void) {
    static const char * const fp_files[] = {
        "/data/data/" TARGET_PKG "/files/tdm_track.dat",
        "/data/data/" TARGET_PKG "/files/tdm_counter",
        "/data/data/" TARGET_PKG "/files/tri_init",
        "/data/data/" TARGET_PKG "/files/TRI_CM_AUDIT",
        "/data/data/" TARGET_PKG "/files/login-identifier.txt",
        "/data/data/" TARGET_PKG "/files/MSDK.mmap3",
        "/data/data/" TARGET_PKG "/files/ace_shell_di.dat",
        "/data/data/" TARGET_PKG "/files/jwt_token.txt",
        "/data/data/" TARGET_PKG "/files/itop_login.txt",
        "/data/data/" TARGET_PKG "/files/.iii",
        "/data/data/" TARGET_PKG "/files/.system_android_l2",
        "/data/user/0/" TARGET_PKG "/files/tdm_track.dat",
        "/data/user/0/" TARGET_PKG "/files/tdm_counter",
        "/data/user/0/" TARGET_PKG "/files/tri_init",
        "/data/user/0/" TARGET_PKG "/files/TRI_CM_AUDIT",
        "/data/user/0/" TARGET_PKG "/files/login-identifier.txt",
        "/data/user/0/" TARGET_PKG "/files/MSDK.mmap3",
        "/data/user/0/" TARGET_PKG "/files/ace_shell_di.dat",
        "/data/user/0/" TARGET_PKG "/files/.iii",
        "/data/user/0/" TARGET_PKG "/files/.system_android_l2",
        "/data/user/0/" TARGET_PKG "/files/apm_qcc_finally",
        NULL
    };
    static const char * const fp_dirs[] = {
        "/data/data/" TARGET_PKG "/files/com.tencent.qimei.sdk.QimeiSDK",
        "/data/data/" TARGET_PKG "/files/com.tencent.tdm.qimei.sdk.QimeiSDK",
        "/data/data/" TARGET_PKG "/files/com.tencent.tbs.qimei.sdk.QimeiSDK",
        "/data/data/" TARGET_PKG "/files/hawk_data",
        "/data/data/" TARGET_PKG "/files/ano_tmp",
        "/data/data/" TARGET_PKG "/files/tdm_tmp",
        "/data/data/" TARGET_PKG "/shared_prefs",
        "/data/data/" TARGET_PKG "/databases",
        "/data/user/0/" TARGET_PKG "/files/com.tencent.qimei.sdk.QimeiSDK",
        "/data/user/0/" TARGET_PKG "/files/com.tencent.tdm.qimei.sdk.QimeiSDK",
        "/data/user/0/" TARGET_PKG "/files/apm_qcc",
        "/data/user/0/" TARGET_PKG "/files/apm_qcc_finally",
        "/data/user/0/" TARGET_PKG "/databases",
        "/data/user/0/" TARGET_PKG "/shared_prefs",
        NULL
    };
    int cnt = 0;
    for (int i = 0; fp_files[i]; i++) cnt += (unlink(fp_files[i]) == 0) ? 1 : 0;
    char cmd[512];
    for (int i = 0; fp_dirs[i]; i++) {
        snprintf(cmd, sizeof(cmd), "rm -rf -- '%s' 2>/dev/null", fp_dirs[i]);
        if (system(cmd) == 0) cnt++;
    }
    OK("[L5] DFM 指纹缓存清理 %d 项", cnt);
}

static int do_prepare(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGHUP, sig_handler);
    /* Normalize forge process name for discretion */
    prctl(PR_SET_NAME, "[kworker/u:0]", 0, 0, 0);
    /* [TASK-06] 启动时加载并验证外置偏移表；失败时保持写入禁用。 */
    load_dyn_table();
    protect_devmode();
    kill_suspicious_procs();
    block_tdm_reporting();  /* ← 新增: iptables 阻断上报 */
    clean_virt_traces();
    stop_game();
    sleep(2);
    /* [v8.7 L5] DFM 指纹缓存清理 — 在游戏停止后立即执行，消除跨会话设备关联 */
    clean_dfm_fingerprints();
    int n = clean_all_ac_files();
    OK("清理文件: %d 个", n);
    restore_dirs();
    adapt_properties();
    /* [v8.7] 深层设备标识重建 (L1–L4) */
    spoof_serial_bind();    /* L1: 内核级 serial mount --bind */
    resetprop_identity();   /* L2: 全局 IMEI/Serial resetprop */
    spoof_oaid_vaid();      /* L3: OAID/VAID 文件替换 */
    spoof_ssaid();          /* L4: SSAID XML 轮换 */
    /* [v8.7] Android ID — settings put 全局写入 */
    {
        /* settings put 在所有 Android 版本均可用，无需 sqlite3 CLI */
        run_shell_best_effort("settings put secure android_id 7a3f9b2c1d4e8f06 2>/dev/null || true");
        OK("[hwid] Android ID 已固定");
    }
    /* v8.7 single-writer order: clear stale wrap preload before launch.
     * forge validates and writes the JSON table first; injector only performs
     * dlopen after that transaction completes. */
    {
        const char *rp = find_resetprop();
        if (rp) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                "%s -d wrap.%s 2>/dev/null || setprop wrap.%s '' 2>/dev/null",
                rp, TARGET_PKG, TARGET_PKG);
            if (system(cmd) == 0)
                OK("[hook] stale wrap.%s preload cleared", TARGET_PKG);
            else
                WARN("[hook] failed to clear stale wrap.%s preload", TARGET_PKG);
        } else {
            char cmd[192];
            snprintf(cmd, sizeof(cmd),
                "setprop wrap.%s '' 2>/dev/null", TARGET_PKG);
            if (system(cmd) == 0)
                OK("[hook] stale wrap.%s preload cleared via setprop", TARGET_PKG);
            else
                WARN("[hook] stale wrap.%s preload could not be cleared", TARGET_PKG);
        }
    }
    protect_devmode();
    return 0;
}

static int do_launch(void) {
    JUNK_INSN();
    do_prepare();
    start_logcat();
    /* Start background behavior monitor (append-only log) */
    run_shell_best_effort("pkill -x forge_monitor 2>/dev/null || true; "
           "/data/local/tmp/forge_monitor -v >> /data/local/tmp/forge_monitor.log 2>&1 &");
    OK("forge_monitor 已启动");
    start_game();
    pid_t pid = 0;
    for (int i = 0; i < 300; i++) {
        pid = get_pid_by_name(TARGET_PKG);
        if (pid) break;
        usleep(100000);
    }
    if (pid) {
        usleep(500000);
        /* Deploy-shell mounts need not propagate into Android app namespaces. */
        apply_identity_namespace(pid);
    }
    /* v8.7 order: namespace overlay -> validated table write -> hook dlopen.
     * injector only performs dlopen and owns no independent offset table. */
    int rc = patch_game_process();
    if (rc != 0) {
        ERR("validated patch transaction failed; hook injection cancelled");
        stop_game();
        run_shell_best_effort("pkill -x forge_monitor 2>/dev/null || true");
        return rc;
    }
    pid = get_pid_by_name(TARGET_PKG);
    if (!pid || inject_hook(pid) != 0) {
        ERR("hook library load failed; stopping inconsistent launch");
        stop_game();
        run_shell_best_effort("pkill -x forge_monitor 2>/dev/null || true");
        return -1;
    }
    hide_injection_from_maps(pid);
    if (pid) {
        safe_trunc(APP_DATA "/files/GPMSDK.mmap3");
        safe_trunc(APP_DATA "/shared_prefs/GCloudCoreSP.xml");
        safe_trunc(APP_DATA "/files/tdm_track.dat");
        safe_trunc(APP_DATA "/shared_prefs/qm_global_sp.xml");
        OK("二次文件清理完成");
    }
    /* B5: 后台每30秒重复清理 — double-fork 避免僵尸进程 */
    if (pid > 0) {
        pid_t mid = fork();
        if (mid == 0) {
            /* 中间进程: 立即 fork 子进程后退出，让 init 接管 */
            pid_t cleaner = fork();
            if (cleaner != 0) _exit(0);  /* 中间进程退出 */
            /* 以下是真正的清理 daemon */
            prctl(PR_SET_NAME, "[kworker/0:2-clean]", 0, 0, 0);

            /* [TASK-02] 两阶段轮询:
             *   注入后前 10s 保持 100ms（等 tersafe 自修复窗口过去）
             *   之后切换: killchain 1s / BSS 500ms / full patch 5s / UE4 2s
             */
            struct timespec ts_inject_done;
            clock_gettime(CLOCK_MONOTONIC, &ts_inject_done);
            /* 各操作的上次执行时间 */
            struct timespec ts_kchain = ts_inject_done;
            struct timespec ts_bss    = ts_inject_done;
            struct timespec ts_full   = ts_inject_done;
            struct timespec ts_ue4    = ts_inject_done;
            #define MS_SINCE(ts_prev) ({ \
                struct timespec _now; clock_gettime(CLOCK_MONOTONIC, &_now); \
                (long)((_now.tv_sec-(ts_prev).tv_sec)*1000 + \
                       (_now.tv_nsec-(ts_prev).tv_nsec)/1000000); })

            while (1) {
                struct timespec ts_now_loop;
                clock_gettime(CLOCK_MONOTONIC, &ts_now_loop);
                long since_inject = (long)((ts_now_loop.tv_sec - ts_inject_done.tv_sec)*1000 +
                                           (ts_now_loop.tv_nsec - ts_inject_done.tv_nsec)/1000000);
                int maintain = (since_inject > 10000); /* >10s 切换到维护阶段 */

                usleep(maintain ? 500000 : 100000); /* 维护阶段 500ms 基础周期 */

                pid_t cp = get_pid_by_name(TARGET_PKG);
                if (cp <= 0) _exit(0);

                /* Targeted file cleanup — 每周期 */
                static const char *kGuardPrecise[] = {
                    APP_DATA "/files/GPMSDK.mmap3",
                    APP_DATA "/shared_prefs/GCloudCoreSP.xml",
                    APP_DATA "/files/tdm_track.dat",
                    APP_DATA "/shared_prefs/qm_global_sp.xml",
                    APP_DATA "/shared_prefs/tdm.xml",
                    APP_DATA "/shared_prefs/tgpa.xml",
                    NULL
                };
                for (int i = 0; kGuardPrecise[i]; i++) safe_trunc(kGuardPrecise[i]);

                /* Layered patch verification */
                {
                    pid_t vp2 = cp;
                    uint64_t ts2  = get_module_base(vp2, C_tersafe);
                    uint64_t ue4b = DYN_UE4_COUNT ? get_module_base(vp2, C_ue4) : 0;
                    if (ue4b && !verify_module_version(vp2, "libUE4.so",
                            g_dyn_table.ue4_build_id))
                        ue4b = 0;

                    /* Validated fast subset: every 1s in maintenance, every loop during injection. */
                    long kchain_interval = maintain ? 1000 : 100;
                    if (ts2 && MS_SINCE(ts_kchain) >= kchain_interval) {
                        clock_gettime(CLOCK_MONOTONIC, &ts_kchain);
                        static const uint64_t kFastOffsets[] = {
                            /* 0x419FDC: 接受tersafe的RET(0xD65F03C0)，停止翻转
                             * MOV X0,#0 和 RET 功能等价(均立即返回截断检测链)
                             * 高频翻转本身是GTI签名，用RET消除写入噪声 */
                            0x419FDC, 0x419FE0, 0x2E7810,
                            0x2F29D0, 0x320D78, 0x3233B8,
                        };
                        for (size_t ci = 0; ci < sizeof(kFastOffsets) / sizeof(kFastOffsets[0]); ci++) {
                            const patch_entry_t *patch = find_validated_patch(kFastOffsets[ci]);
                            if (!patch) continue;
                            uint32_t cur = 0;
                            if (mem_read32(vp2, ts2 + patch->offset, &cur) == 0
                                && cur != patch->value) {
                                WARN("patch reverted off=0x%llx cur=0x%08x — repatch",
                                     (unsigned long long)patch->offset, cur);
                                safe_verify_and_write(vp2, ts2 + patch->offset, patch);
                            }
                        }
                    }

                    /* Full code patch: 每 5s (维护) 或 每 300ms (注入窗口) */
                    long full_interval = maintain ? 5000 : 300;
                    if (ts2 && MS_SINCE(ts_full) >= full_interval) {
                        clock_gettime(CLOCK_MONOTONIC, &ts_full);
                        for (size_t i = 0; i < DYN_TERSAFE_COUNT; i++) {
                            uint32_t cur = 0;
                            if (mem_read32(vp2, ts2 + DYN_TERSAFE_PATCHES[i].offset, &cur) == 0
                                && cur != DYN_TERSAFE_PATCHES[i].value) {
                                WARN("code patch reverted off=0x%llx — repatch",
                                     (unsigned long long)DYN_TERSAFE_PATCHES[i].offset);
                                safe_verify_and_write(vp2,
                                    ts2 + DYN_TERSAFE_PATCHES[i].offset,
                                    &DYN_TERSAFE_PATCHES[i]);
                            }
                        }
                    }

                    /* BSS 清零: 每 500ms (维护) 或 每周期 (注入窗口) */
                    long bss_interval = maintain ? 500 : 100;
                    if (ts2 && MS_SINCE(ts_bss) >= bss_interval) {
                        clock_gettime(CLOCK_MONOTONIC, &ts_bss);
                        uint64_t bss2 = get_module_base(vp2, "libtersafe.so:bss");
                        if (bss2) {
                            for (size_t i = 0; i < DYN_BSS_COUNT; i++) {
                                uint32_t cur = 0;
                                if (mem_read32(vp2, bss2 + DYN_BSS_OFFSETS[i], &cur) == 0
                                    && cur != 0) {
                                    safe_write32(vp2, bss2 + DYN_BSS_OFFSETS[i], 0, 3);
                                }
                            }
                        }
                    }

                    /* UE4: 每 2s (维护) 或 每 200ms (注入窗口) */
                    long ue4_interval = maintain ? 2000 : 200;
                    if (ue4b && MS_SINCE(ts_ue4) >= ue4_interval) {
                        clock_gettime(CLOCK_MONOTONIC, &ts_ue4);
                        for (size_t i = 0; i < DYN_UE4_COUNT; i++) {
                            uint32_t cur = 0;
                            if (mem_read32(vp2, ue4b + DYN_UE4_PATCHES[i].offset, &cur) == 0
                                && cur != DYN_UE4_PATCHES[i].value) {
                                safe_verify_and_write(vp2,
                                    ue4b + DYN_UE4_PATCHES[i].offset,
                                    &DYN_UE4_PATCHES[i]);
                            }
                        }
                    }
                }
            }
            #undef MS_SINCE
        }
        /* 回收中间进程，避免僵尸 */
        if (mid > 0) waitpid(mid, NULL, 0);
    }
    return rc;
}

/* ============= [v7.0 P2-2] TCP SipHash-2-4 认证 =============
 * 防止同机其他进程伪造控制命令（stop/patch 等）
 * 协议: AUTH:<16hex_nonce>:<16hex_mac>\n<cmd>\n
 * key:  /data/local/tmp/.forge_key (16字节随机数，chmod 600) */
#define SESSION_KEY_FILE C_session_key
#define SESSION_KEY_LEN  16

static uint8_t g_session_key[SESSION_KEY_LEN] = {0};
static int     g_auth_enabled = 0;

/* SipHash-2-4: 轻量 MAC，无外部依赖 */
static uint64_t siphash24(const uint8_t *k16, const uint8_t *data, size_t len) {
    uint64_t k0, k1;
    memcpy(&k0, k16, 8); memcpy(&k1, k16+8, 8);
#define ROT64(v,n) (((v)<<(n))|((v)>>(64-(n))))
#define SR() do{ \
    v0+=v1;v1=ROT64(v1,13);v1^=v0;v0=ROT64(v0,32); \
    v2+=v3;v3=ROT64(v3,16);v3^=v2; \
    v0+=v3;v3=ROT64(v3,21);v3^=v0; \
    v2+=v1;v1=ROT64(v1,17);v1^=v2;v2=ROT64(v2,32); \
}while(0)
    uint64_t v0=0x736f6d6570736575ULL^k0, v1=0x646f72616e646f6dULL^k1;
    uint64_t v2=0x6c7967656e657261ULL^k0, v3=0x7465646279746573ULL^k1;
    const uint8_t *e = data + len - (len%8);
    for (; data<e; data+=8) { uint64_t m; memcpy(&m,data,8); v3^=m;SR();SR();v0^=m; }
    uint64_t last = (uint64_t)len<<56;
    int r=(int)(len%8); for(int i=r-1;i>=0;i--) last|=((uint64_t)data[i])<<(i*8);
    v3^=last;SR();SR();v0^=last; v2^=0xFF;
    for(int i=0;i<4;i++) SR();
    return v0^v1^v2^v3;
#undef ROT64
#undef SR
}

static void init_session_key(void) {
    int fd = open(SESSION_KEY_FILE, O_RDONLY);
    if (fd >= 0) { ssize_t n=read(fd,g_session_key,SESSION_KEY_LEN); close(fd);
        if (n==SESSION_KEY_LEN) { g_auth_enabled=1; return; } }
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { WARN("无法读 /dev/urandom，认证禁用"); return; }
    ssize_t n = read(fd, g_session_key, SESSION_KEY_LEN); close(fd);
    if (n != SESSION_KEY_LEN) return;
    fd = open(SESSION_KEY_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0 || write_all_fd(fd, g_session_key, SESSION_KEY_LEN) != 0) {
        if (fd >= 0) close(fd);
        WARN("session key cannot be persisted; authentication disabled");
        memset(g_session_key, 0, sizeof(g_session_key));
        return;
    }
    close(fd);
    g_auth_enabled = 1;
    OK("session key 生成: %s", SESSION_KEY_FILE);
}

/* 验证并剥离 AUTH 前缀，返回实际命令指针；NULL=认证失败 */
static const char *verify_auth(char *buf) {
    if (!g_auth_enabled) return buf;
    if (strncmp(buf, "AUTH:", 5) != 0) { WARN("auth required"); return NULL; }
    char *colon1 = strchr(buf+5, ':');
    if (!colon1) return NULL;
    char *nl = strchr(colon1+1, '\n');
    if (!nl) return NULL;
    if ((size_t)(colon1-(buf+5)) != 16 || (size_t)(nl-(colon1+1)) != 16) return NULL;
    uint8_t nonce[8];
    for (int i=0;i<8;i++) { char h[3]={buf[5+i*2],buf[5+i*2+1],0}; nonce[i]=(uint8_t)strtoul(h,NULL,16); }
    const char *cmd = nl+1;
    size_t clen = strlen(cmd); if (clen>256) clen=256;
    uint8_t combined[8+256]; memcpy(combined,nonce,8); memcpy(combined+8,cmd,clen);
    uint64_t exp = siphash24(g_session_key, combined, 8+clen);
    char mh[17]={0}; memcpy(mh, colon1+1, 16);
    uint64_t got = (uint64_t)strtoull(mh, NULL, 16);
    if ((exp^got) != 0) { WARN("auth MAC mismatch"); return NULL; }
    return cmd;
}

/* ============= [v7.1 P5] TCP opcode 无痕通信 ===================
 * 防: TCP 流量分析 — 原来的命令名 "ping"/"launch" 明文可见。
 * 协议 v2 (opcode-based):
 *   客户端: [AUTH_HEADER\n] <1-byte opcode> \n
 *   服务端: {"s":"ok","v":"8.7"} (缩短字段名)
 *
 * Opcode 表:
 *   0x01 ping    0x02 prepare  0x03 launch  0x04 patch
 *   0x05 stop    0x06 status   0x07 clean   0x08 adapt
 *   0xFF 查看支持的命令列表 (兼容旧 text-mode)
 *
 * 响应 JSON 缩短字段:
 *   status → s  |  version → v  |  msg → m
 *   game_running → g  |  pid → p  |  uid → u
 * ============================================================= */
#define OP_PING    0x01
#define OP_PREPARE 0x02
#define OP_LAUNCH  0x03
#define OP_PATCH   0x04
#define OP_STOP    0x05
#define OP_STATUS  0x06
#define OP_CLEAN   0x07
#define OP_ADAPT   0x08

static int handle_command(const char *req, char *resp, size_t resp_sz) {
    /* 检测 opcode 还是 text: 单字节且在 0x01-0x08/0xFF 范围 */
    unsigned char op = (unsigned char)req[0];
    int is_opcode = (op >= 0x01 && op <= 0x08) || op == 0xFF;

    /* text-mode 兼容: 将 text 命令映射到 opcode */
    if (!is_opcode) {
        if (strncmp(req,"ping",4)==0)    op=OP_PING;
        else if (strncmp(req,"prepare",7)==0) op=OP_PREPARE;
        else if (strncmp(req,"launch",6)==0)  op=OP_LAUNCH;
        else if (strncmp(req,"patch",5)==0)   op=OP_PATCH;
        else if (strncmp(req,"stop",4)==0)    op=OP_STOP;
        else if (strncmp(req,"status",6)==0)  op=OP_STATUS;
        else if (strncmp(req,"clean",5)==0)   op=OP_CLEAN;
        else if (strncmp(req,"adapt",5)==0)   op=OP_ADAPT;
        else op=0xFF;
    }

    switch (op) {
    case OP_PING:
        snprintf(resp, resp_sz, "{\"s\":\"ok\",\"v\":\"" FORGE_VERSION "\"}");
        break;
    case OP_PREPARE:
        if (getuid() != 0) { snprintf(resp, resp_sz, "{\"s\":\"err\",\"m\":\"root\"}"); break; }
        do_prepare();
        snprintf(resp, resp_sz, "{\"s\":\"ok\",\"m\":\"prep\"}");
        break;
    case OP_LAUNCH:
        if (getuid() != 0) { snprintf(resp, resp_sz, "{\"s\":\"err\",\"m\":\"root\"}"); break; }
        { int rc = do_launch();
          snprintf(resp, resp_sz, "{\"s\":\"%s\",\"m\":\"%s\"}",
              rc==0?"ok":"partial", rc==0?"ok":"partial"); }
        break;
    case OP_PATCH:
        { int rc = patch_game_process();
          snprintf(resp, resp_sz, "{\"s\":\"%s\"}", rc==0?"ok":"partial"); }
        break;
    case OP_STOP:
        stop_game();
        snprintf(resp, resp_sz, "{\"s\":\"ok\"}");
        break;
    case OP_STATUS:
        { int run = target_is_running();
          pid_t pid = run ? get_pid_by_name(TARGET_PKG) : 0;
          snprintf(resp, resp_sz, "{\"s\":\"ok\",\"g\":%s,\"p\":%d,\"u\":%d}",
              run?"true":"false", pid, getuid()); }
        break;
    case OP_CLEAN:
        { int n = clean_all_ac_files();
          snprintf(resp, resp_sz, "{\"s\":\"ok\",\"c\":%d}", n); }
        break;
    case OP_ADAPT:
        adapt_properties();
        snprintf(resp, resp_sz, "{\"s\":\"ok\"}");
        break;
    default:
        snprintf(resp, resp_sz,
            "{\"s\":\"ok\",\"ops\":[1,2,3,4,5,6,7,8]}");
        break;
    }
    return 0;
}

/* TCP socket 单连接处理循环 */
static int run_tcp_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { ERR("socket failed"); return -1; }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CTRL_PORT);
    addr.sin_addr.s_addr = inet_addr(CTRL_HOST);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ERR("bind %s:%d failed", CTRL_HOST, CTRL_PORT);
        close(fd);
        return -1;
    }
    if (listen(fd, 5) < 0) { ERR("listen failed"); close(fd); return -1; }
    OK("TCP server listening on %s:%d", CTRL_HOST, CTRL_PORT);

    /* [TASK-07] UDS IPC server — forge_monitor 告警实时通知 */
#define FORGE_IPC_SOCK "/data/local/tmp/forge_ipc.sock"
    int ufd = -1;
    {
        unlink(FORGE_IPC_SOCK);
        ufd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ufd >= 0) {
            struct sockaddr_un uaddr;
            memset(&uaddr, 0, sizeof(uaddr));
            uaddr.sun_family = AF_UNIX;
            strncpy(uaddr.sun_path, FORGE_IPC_SOCK, sizeof(uaddr.sun_path)-1);
            if (bind(ufd, (struct sockaddr*)&uaddr, sizeof(uaddr)) == 0 && listen(ufd, 4) == 0) {
                /* 非阻塞，不阻塞 TCP accept 循环 */
                int fl = fcntl(ufd, F_GETFL, 0);
                if (fl >= 0) fcntl(ufd, F_SETFL, fl | O_NONBLOCK);
                OK("[IPC] UDS server listening: %s", FORGE_IPC_SOCK);
            } else {
                close(ufd); ufd = -1;
                WARN("[IPC] UDS bind/listen failed");
            }
        }
    }

    while (1) {
        /* 先检查 UDS IPC 连接（非阻塞） */
        if (ufd >= 0) {
            int ucfd = accept(ufd, NULL, NULL);
            if (ucfd >= 0) {
                char ibuf[256] = {0};
                ssize_t in = recv(ucfd, ibuf, sizeof(ibuf)-1, 0);
                if (in > 0) {
                    OK("[IPC] alert from monitor: %.120s", ibuf);
                /* An alert triggers one validated code-table restore. */
                    pid_t vp = get_pid_by_name(TARGET_PKG);
                    if (vp > 0) {
                        uint64_t ts2 = get_module_base(vp, C_tersafe);
                        if (ts2) {
                            static const uint64_t kFastOffsets[] = {
                                0x419FDC, 0x419FE0, 0x2E7810,
                                0x2F29D0, 0x320D78, 0x3233B8,
                            };
                            int repatch = 0;
                            for (size_t ci = 0; ci < sizeof(kFastOffsets) / sizeof(kFastOffsets[0]); ci++) {
                                const patch_entry_t *patch = find_validated_patch(kFastOffsets[ci]);
                                if (!patch) continue;
                                uint32_t cur = 0;
                                if (mem_read32(vp, ts2 + patch->offset, &cur) == 0
                                    && cur != patch->value) {
                                    if (safe_verify_and_write(vp, ts2 + patch->offset, patch) == 0)
                                        repatch++;
                                }
                            }
                            if (repatch > 0)
                                OK("[IPC] emergency repatch: %d/6 sites", repatch);
                        }
                    }
                }
                close(ucfd);
            }
        }

        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int cfd = accept(fd, (struct sockaddr*)&cli, &cli_len);
        if (cfd < 0) continue;

        char buf[4096] = {0};
        ssize_t n = recv(cfd, buf, sizeof(buf)-1, 0);
        if (n > 0) {
            buf[n] = 0;
            /* [v7.0 P2-2] 认证验证：剥离 AUTH 前缀，无效则拒绝 */
            const char *cmd_ptr = verify_auth(buf);
            if (!cmd_ptr) {
                const char *deny = "{\"status\":\"err\",\"msg\":\"auth failed\"}\n";
                send(cfd, deny, strlen(deny), 0);
                close(cfd); continue;
            }
            /* 复制命令到可写缓冲 */
            char cmd_buf[4096] = {0};
            strncpy(cmd_buf, cmd_ptr, sizeof(cmd_buf)-1);
            char *nl = strchr(cmd_buf, '\n'); if (nl) *nl = 0;
            nl = strchr(cmd_buf, '\r'); if (nl) *nl = 0;

            char resp[4096];
            handle_command(cmd_buf, resp, sizeof(resp));
            send(cfd, resp, strlen(resp), 0);
        }
        close(cfd);
    }
    if (ufd >= 0) close(ufd);
    close(fd);
    return 0;
}

/* ============= main ============= */
static void print_usage(const char *prog) {
    fprintf(stderr,
        FORGE_VERSION_STR " — 三角洲行动 运行环境管理\n"
        "用法: %s [选项]\n"
        "  -d    daemon/TCP 服务器 (端口 %d)\n"
        "  -p    仅 prepare (清理+适配+属性)\n"
        "  -l    launch (prepare + 启动游戏 + 补丁)\n"
        "  -m    仅补丁 (游戏必须在运行)\n"
        "  -s    查询状态\n"
        "  -c    仅清理检查文件\n"
        "  -x    仅适配系统属性\n"
        "  -v    详细日志\n"
        "  -h    显示帮助\n",
        prog, CTRL_PORT);
}

int main(int argc, char **argv) {
    disguise_self();
    srand((unsigned int)(time(NULL) ^ (unsigned long)getpid()));
    /* [v7.0 P2-2] 初始化 session key（daemon 模式前执行）*/
    init_session_key();

    int daemon_mode = 0, flag_prep = 0, flag_launch = 0, flag_patch = 0,
        flag_status = 0, flag_clean = 0, flag_adapt = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) g_verbose = 1;
        else if (!strcmp(argv[i], "-d")) daemon_mode = 1;
        else if (!strcmp(argv[i], "-p")) flag_prep = 1;
        else if (!strcmp(argv[i], "-l")) flag_launch = 1;
        else if (!strcmp(argv[i], "-m")) flag_patch = 1;
        else if (!strcmp(argv[i], "-s")) flag_status = 1;
        else if (!strcmp(argv[i], "-c")) flag_clean = 1;
        else if (!strcmp(argv[i], "-x")) flag_adapt = 1;
        else if (!strcmp(argv[i], "-h")) { print_usage(argv[0]); return 0; }
    }

    if (daemon_mode) {
        if (getuid() != 0) { ERR("daemon 模式需要 root 权限"); return 1; }
        g_logfile = fopen(FORGE_LOG, "a");
        load_dyn_table();
        OK("DeltaForge daemon v" FORGE_VERSION " 启动");
        return run_tcp_server();
    }

    if (getuid() != 0) { ERR("需要 root 权限"); return 1; }

    g_logfile = fopen(FORGE_LOG, "a");

    if (flag_launch) { return do_launch(); }
    if (flag_prep)   { do_prepare(); return 0; }
    if (flag_patch)  { load_dyn_table(); return patch_game_process(); }
    if (flag_status) {
        int r = target_is_running();
        printf("game_running=%d pid=%d\n", r, r ? get_pid_by_name(TARGET_PKG) : 0);
        return 0;
    }
    if (flag_clean) { int n = clean_all_ac_files(); OK("cleaned %d files", n); return 0; }
    if (flag_adapt) { adapt_properties(); return 0; }

    /* 无参数 = 默认一次性 launch */
    do_prepare();
    start_game();
    patch_game_process();
    return 0;
}
