// ============================================================
// 法器: DeltaForge/cloud-agent/native/forge.c v5.6
// 描述: 三角洲行动云手机过检测核心 - 完整内存补丁 + 环境伪装 + 文件清理
// 编译: aarch64-linux-android21-clang -static -Os -o forge forge.c
//   或: 云手机内 gcc -static -Os -o forge forge.c
// 调用者:
//   1. 自身内嵌 TCP server (run_tcp_server, port 9510) — 手机端 app 通过 socket 发 JSON 命令
//   2. 云手机内直接命令行: ./forge -l (全流程), ./forge -d (daemon), ./forge -m (仅补丁)
//   3. 手机端 Python runner 通过 adb push + adb shell 远程调用
// 读写数据:
//   读: /proc/[pid]/maps, /proc/[pid]/mem, /proc/[pid]/cmdline, /proc 目录枚举
//   写: /proc/[pid]/mem (4字节 ARM64 机器码), 游戏 /data/data/ 目录文件删除/清空
//   写: 系统属性 (setprop/resetprop 伪装为 Xiaomi 23049RAD8C)
// ============================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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

/* ============= 配置项 ============= */
#define TARGET_PKG          "com.tencent.tmgp.dfm"
#define APP_DATA            "/data/data/" TARGET_PKG

/* 控制服务器地址 (手机 app 通过 adb forward 连接) */
#define CTRL_HOST           "127.0.0.1"
#define CTRL_PORT           9510
#define FORGE_VERSION       "5.6"
#define FORGE_LOG           "/data/local/tmp/forge.log"
#define DETECT_LOG          "/data/local/tmp/detect_now.log"

static void start_logcat(void) {
    system("killall logcat 2>/dev/null; sleep 0.5");
    system("logcat -c 2>/dev/null; "
           "logcat -v time 2>/dev/null | "
           "grep -iE 'tersafe|TSS|ACE|Qimei|TGPA|GCloud|MSDK|TDM|"
           "anti.cheat|forbid|ban|frozen|kicked|emulator|"
           "fingerprint|hardware|manufacturer|device_id' "
           "> " DETECT_LOG " 2>&1 &");
    fprintf(stderr, "[+] antidetect log: %s\n", DETECT_LOG);
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

/* ============= 内存补丁条目 ============= */
typedef struct { uint64_t offset; uint32_t value; } patch_entry_t;

/* --- libtersafe.so (TSS/ACE 核心) 代码段补丁，61 处 ---
 * 基于 delta_force_detection_final_static_report.md 中的 offset 表
 * 0x2A1F03FF = MOV W0, #0x0FF → 返回 W0=255 (模拟检测通过)
 * 0xD61F03C0 = BR X30 → 直接跳转返回 (跳过检测函数体)
 * 0xD65F03C0 = RET → 空函数返回
 * 0x1400000X = B #offset → 无条件跳转绕过检测分支
 * 0x38400XXX = LDRB Wx, [Xsp, #N] → 改为读取栈偏移(值趋于0), 原指令读敏感文件/proc节点
 */
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
    /* kill chain full coverage - 6 nodes from detect entry to tgkill exit */
    {0x419FDC, 0xD2800000},  /* detect entry -> MOV X0,#0 (report clean) */
    {0x419FE0, 0xD65F03C0},  /* detect+4 -> RET */
    {0x2E7810, 0xD65F03C0},  /* kill dispatch -> RET */
    {0x2F29D0, 0xD65F03C0},  /* kill router -> RET */
    {0x320D78, 0xD65F03C0},  /* kill wrapper -> RET */
    {0x3233B8, 0xD65F03C0},  /* tgkill call site -> RET */

#define TERSAFE_PATCH_COUNT (sizeof(kTersafePatches)/sizeof(kTersafePatches[0]))

/* --- libtersafe.so BSS 段全局检测变量偏移，共 40 个 ---
 * 写入 0 清空 TSS 内部检测状态标记
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

/* --- libUE4.so 引擎内置检测补丁，6 处 ---
 * 全部使用 0xD65F03C0 (RET) 安全返回，不触发 SIGILL
 */static const patch_entry_t kUE4Patches[] = {
    {0x1347F7F0, 0xD65F03C0}, {0x1347F7F4, 0xD65F03C0},
    {0x13537034, 0xD65F03C0}, {0x13537038, 0xD65F03C0},
    {0x13567E38, 0xD65F03C0}, {0x13567E3C, 0xD65F03C0},
};
#define UE4_PATCH_COUNT (sizeof(kUE4Patches)/sizeof(kUE4Patches[0]))

/* ============= 需清理的反作弊目录 ============= */
static const char *kPurgeDirs[] = {
    APP_DATA "/files/ano_tmp",
    APP_DATA "/files/tdm_tmp",
    APP_DATA "/app_crashSight",
    APP_DATA "/files/UE4Game/DeltaForce/DeltaForce/Saved/Config/CrashReportClient",
    APP_DATA "/files/UE4Game/DeltaForce/DeltaForce/Saved/LoadTrack",
    APP_DATA "/files/perfsight",
    NULL
};

/* ============= 需精确删除的文件 ============= */
static const char *kPreciseDeleteFiles[] = {
    APP_DATA "/files/qm/5093f053c62f9ae1",
    APP_DATA "/files/qm/cm_ce15c95bcb0c04db3e0b278bc0f80daf",
    APP_DATA "/files/tdm_track.dat",
    APP_DATA "/files/GPMSDK.mmap3",
    APP_DATA "/files/com.tencent.tdm.qimei.sdk.QimeiSDK",
    APP_DATA "/databases/crashSight_db_",
    APP_DATA "/shared_prefs/GCloudCoreSP.xml",
    APP_DATA "/shared_prefs/itop.xml",
    APP_DATA "/shared_prefs/tdm.xml",
    APP_DATA "/shared_prefs/tgpa.xml",
    APP_DATA "/shared_prefs/qm_global_sp.xml",
    APP_DATA "/shared_prefs/QV1com.tencent.tdm.qimei.sdk.QimeiSDKc2009844da43a85e.xml",
    APP_DATA "/shared_prefs/lastBufferedMaps.xml",
    "/sdcard/.imei",
    NULL
};

static const char *kExtraDeleteFiles[] = {
    APP_DATA "/files/ano_tmp/tp_report.dat",
    APP_DATA "/files/ano_tmp/ano_sc.dat",
    APP_DATA "/files/ano_tmp/ano_id.dat",
    APP_DATA "/files/MSDK_GUID",
    APP_DATA "/files/.beacon_id",
    APP_DATA "/files/.tbs_guid",
    APP_DATA "/files/tpns_guid",
    APP_DATA "/files/bugly_crash",
    APP_DATA "/files/bugly_anr",
    NULL
};

/* 仅在这些指定目录内做模糊匹配，不递归整个 APP_DATA */
static const char *kScanDirs[] = {
    APP_DATA "/files/qm",
    APP_DATA "/files/ano_tmp",
    APP_DATA "/files/tdm_tmp",
    /* dg-patch 移除：可能存游戏增量补丁，不扫描 */
    APP_DATA "/shared_prefs",
    APP_DATA "/databases",
    NULL
};
static const char *kPatternSubstrings[] = { "tdm", "hawk", "qv1", "lcc", "qc_", "qm_", NULL };
static const char *kQmDir = APP_DATA "/files/qm";
/* "q"/"lc"/"qm" 前缀过短/过宽已收紧，避免误删游戏合法文件 */
static const char *kQmPrefixes[] = { "cm_", "QV1", "lccNo", "qm_", NULL };

/* ============= qm 目录匹配规则 =============
 * 原规则只匹配 cm_* 前缀，但 QimeiSDK 在文件中写入 QV1* / lccNoCN / q* 等前缀
 * 现在用多个前缀匹配，覆盖 cm_ / QV1 / q / lc / qm 开头
 */
static int match_qm_prefix(const char *name) {
    for (int i = 0; kQmPrefixes[i]; i++) {
        size_t pl = strlen(kQmPrefixes[i]);
        if (pl > 0 && strncmp(name, kQmPrefixes[i], pl) == 0)
            return 1;
    }
    return 0;
}

/* ============= 系统属性伪装 =============
 * 云手机常见的暴露属性 → 删除或改写为 Xiaomi 23049RAD8C (Redmi K60)
 * 属性名和值均来自 kSpoofProps 表
 */
typedef struct {
    const char *key;
    const char *value;  /* NULL = 删除此属性 */
} prop_spoof_t;

static const prop_spoof_t kSpoofProps[] = {
    /* --- 云手机/模拟器特征: 删除 --- */
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
    /* --- 云手机平台特征: 删除 --- */
    {"ro.hardware.gralloc", NULL},
    {"ro.hardware.egl", NULL},
    {"ro.product.base_version", NULL},
    {"ro.product.odm.brand", NULL},
    {"ro.product.odm.device", NULL},
    {"ro.product.odm.manufacturer", NULL},
    {"ro.product.odm.model", NULL},
    {"ro.product.odm.name", NULL},
    {"ro.product.odm_dlkm.brand", NULL},
    {"ro.product.odm_dlkm.device", NULL},
    {"ro.product.odm_dlkm.manufacturer", NULL},
    {"ro.product.odm_dlkm.model", NULL},
    {"ro.product.odm_dlkm.name", NULL},
    {"ro.product.product.brand", NULL},
    {"ro.product.product.device", NULL},
    {"ro.product.product.manufacturer", NULL},
    {"ro.product.product.model", NULL},
    {"ro.product.product.name", NULL},
    {"ro.product.ota.host", NULL},
    {"ro.build.characteristics", NULL},
    /* --- 伪装为 Samsung Galaxy S10 (SM-G9730) — 与底层 beyond1q fingerprint 一致 --- */
    {"ro.product.manufacturer", "samsung"},
    {"ro.product.model", "SM-G9730"},
    {"ro.product.device", "beyond1q"},
    {"ro.product.name", "beyond1qltezc"},
    {"ro.build.product", "beyond1q"},
    {"ro.product.brand", "samsung"},
    {"ro.hardware", "qcom"},
    {"ro.board.platform", "msmnile"},
    {"ro.product.board", "msmnile"},
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

static void close_mem(int fd);

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
    int fd = open_mem(pid, O_RDWR);
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

/* 轮询等待 so 加载, timeout_ms 超时返回 0 */
static uint64_t wait_for_module(pid_t pid, const char *mod, int timeout_ms) {
    for (int e = 0; e < timeout_ms; e += 100) {
        uint64_t b = get_module_base(pid, mod);
        if (b) return b;
        usleep(100000);
    }
    return 0;
}

/* ============= 进程查找: /proc 遍历 + cmdline 匹配 ============= */
static pid_t get_pid_by_name(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *ent;
    pid_t r = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        char p[256];
        snprintf(p, sizeof(p), "/proc/%s/cmdline", ent->d_name);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {0};
        read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (strstr(buf, name)) { r = (pid_t)atoi(ent->d_name); break; }
    }
    closedir(d);
    return r;
}

static int target_is_running(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *ent;
    int f = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        char p[256];
        snprintf(p, sizeof(p), "/proc/%s/cmdline", ent->d_name);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {0};
        read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (strstr(buf, TARGET_PKG)) { f = 1; break; }
    }
    closedir(d);
    return f;
}

/* ============= 文件系统递归删除 ============= */
static int rm_recursive(const char *path) {
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

static void purge_dir_contents(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        rm_recursive(full);
    }
    closedir(d);
}

static int delete_matching(const char *dir, const char *substr) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            n += delete_matching(full, substr);
            if (strstr(ent->d_name, substr)) { rm_recursive(full); n++; }
        } else if (strstr(ent->d_name, substr)) {
            unlink(full); n++;
        }
    }
    closedir(d);
    return n;
}

/* ============= Shell 命令执行 ============= */
static int run_cmd(const char *argv[]) {
    pid_t p = fork();
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

/* ============= 系统属性伪装 ============= */

/* 查找 resetprop 二进制 (Magisk 路径不在默认 PATH 里) */
static const char *find_resetprop(void) {
    static char rp[128] = {0};
    if (rp[0]) return rp;
    static const char *cands[] = {
        "/data/adb/magisk/resetprop",
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

static void spoof_properties(void) {
    const char *rp = find_resetprop();
    if (!rp) WARN("未找到 resetprop — ro.* 只读属性无法修改，libforgehook hook 兜底");

    int ok = 0, fail = 0;
    for (const prop_spoof_t *s = kSpoofProps; s->key; s++) {
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
    OK("属性伪装完成 — resetprop=%s ok=%d fail=%d",
       rp ? rp : "N/A", ok, fail);
}

/* ============= 云手机虚拟化痕迹文件清理 ============= */
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

/* ============= 反作弊文件批量清理 ============= */
static int clean_all_ac_files(void) {
    int total = 0;
    for (int i = 0; kPurgeDirs[i]; i++) purge_dir_contents(kPurgeDirs[i]);
    for (int i = 0; kPreciseDeleteFiles[i]; i++) { unlink(kPreciseDeleteFiles[i]); total++; }
    for (int i = 0; kExtraDeleteFiles[i]; i++) { unlink(kExtraDeleteFiles[i]); total++; }

    DIR *d = opendir(kQmDir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (match_qm_prefix(ent->d_name)) {
                char full[4096];
                snprintf(full, sizeof(full), "%s/%s", kQmDir, ent->d_name);
                unlink(full); total++;
            }
        }
        closedir(d);
    }
    for (int i = 0; kScanDirs[i]; i++) {
        for (int j = 0; kPatternSubstrings[j]; j++)
            total += delete_matching(kScanDirs[i], kPatternSubstrings[j]);
    }
    /* 不再递归全 APP_DATA 删除 >4MB 文件 */
    return total;
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

/* ============= 进程伪装 (prctl 改名) ============= */
static void disguise_self(void) {
    prctl(PR_SET_NAME, "[kworker/0:1-mm]", 0, 0, 0);
}

/* ============= 保护 ADB / 开发者模式 ============= */
static void protect_devmode(void) {
    system("settings put global adb_enabled 1 2>/dev/null");
    system("settings put global development_settings_enabled 1 2>/dev/null");
    system("setprop persist.sys.usb.config adb 2>/dev/null");
    system("setprop persist.sys.vold_app_data_isolation_enabled 0 2>/dev/null");
}

/* ============= iptables 清理 =============
 * 移除此前版本遗留的阻断规则，避免游戏无法联网。
 * 反作弊数据拦截改由 libforgehook.so 的 null_redir() 在进程内完成。
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
        system(cmd);
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
        system(cmd);
    }
    OK("iptables 旧规则已清理，游戏网络不受影响 (uid=%s)", uid_buf[0] ? uid_buf : "N/A");
}

/* ============= /proc/self/maps 注入行隐藏 =============
 * 在游戏进程启动后，写 /proc/self/mem 将 maps 中 libforgehook.so 行覆盖为空
 * 注意: 此操作由 libforgehook.so 的 .init 构造函数自动执行，
 * 但也可以通过 forge.c 的 ptrace 方式从外部注入隐藏。
 *
 * 当前采用两重防护:
 *   1. libforgehook.so init: madvise(MADV_DONTDUMP) 标记自己的映射区域
 *   2. forge.c 外部: 写 /proc/PID/mem 中 maps 行内容为零字节
 */
static void hide_injection_from_maps(pid_t pid) {
    if (pid <= 0) return;

    char map_path[64];
    snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(map_path, "r");
    if (!maps) return;

    char line[2048];
    int fd_mem = open_mem(pid, O_RDWR);
    if (fd_mem < 0) { fclose(maps); return; }

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libforgehook") || strstr(line, "libforge")) {
            /* 解析起始地址 */
            uint64_t addr = strtoull(line, NULL, 16);
            uint64_t end = 0;
            char *dash = strchr(line, '-');
            if (dash) end = strtoull(dash + 1, NULL, 16);

            size_t len = end - addr;
            if (len > 0 && len < 1024 * 1024) {
                /* 用零覆盖映射区域中 so 的标识特征 */
                /* 只覆盖 ELF header magic + section name table */
                char zero[16] = {0};
                lseek(fd_mem, addr, SEEK_SET);
                write(fd_mem, zero, sizeof(zero) > len ? len : sizeof(zero));
                WARN("已隐藏 maps 注入行: 0x%llx-0x%llx", (unsigned long long)addr, (unsigned long long)end);
            }
        }
    }
    fclose(maps);
    close_mem(fd_mem);
}

static void close_mem(int fd) {
    if (fd >= 0) {
        close(fd);
        if (g_mem_fd == fd) g_mem_fd = -1;
    }
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
    system(buf);
    snprintf(buf, sizeof(buf), "killall -9 %s 2>/dev/null", TARGET_PKG);
    system(buf);
}

static void start_game(void) {
    char buf[1024];

    /* Step 0: 尝试 wrap 属性 — 让系统在进程启动时 LD_PRELOAD hook 库 */
    snprintf(buf, sizeof(buf),
        "setprop wrap.%s 'LD_PRELOAD=/data/local/tmp/libforgehook.so' 2>/dev/null",
        TARGET_PKG);
    system(buf);
    OK("尝试 wrap LD_PRELOAD: %s", TARGET_PKG);

    /* Step 1: 裸启游戏 */
    snprintf(buf, sizeof(buf),
        "am start -n %s/com.epicgames.ue4.SplashActivity 2>/dev/null",
        TARGET_PKG);
    system(buf);
    OK("游戏已启动，等待进程出现后注入...");
}

/*
 * stage_hook_so: 把 libforgehook.so 复制到游戏的 native lib 目录
 * 绕过 Android 8+ linker namespace 隔离:
 *   dlopen("/data/local/tmp/...") → 失败（不在 app namespace）
 *   dlopen("/data/app/.../lib/arm64/...") → 成功（已在 app namespace）
 */
static void stage_hook_so(pid_t pid, char *out_path, size_t out_sz) {
    strncpy(out_path, "/data/local/tmp/libforgehook.so", out_sz - 1);
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

    char cmd[1600];
    snprintf(cmd, sizeof(cmd),
        "cp /data/local/tmp/libforgehook.so '%s' && chmod 755 '%s' && "
        "restorecon '%s' 2>/dev/null; true",
        dst, dst, dst);
    if (system(cmd) == 0) {
        strncpy(out_path, dst, out_sz - 1);
        out_path[out_sz - 1] = '\0';
        OK("hook 库暂存到 app lib 目录 (绕 namespace): %.80s", out_path);
    } else {
        WARN("hook 库暂存失败，保持原路径");
    }
}

static int inject_hook(pid_t pid) {
    char hook_path[768];
    stage_hook_so(pid, hook_path, sizeof(hook_path));
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "/data/local/tmp/injector %d '%s'", pid, hook_path);
    int rc = system(cmd);
    return (rc == 0) ? 0 : -1;
}

/* ============= 核心: 内存补丁执行 ============= */
static int patch_game_process(void) {
    pid_t pid = 0;
    for (int i = 0; i < 600; i++) {  /* 等待最多 60 秒，覆盖冷启动 */
        pid = get_pid_by_name(TARGET_PKG);
        if (pid) break;
        usleep(100000);
    }
    if (!pid) { WARN("未找到游戏进程"); return -1; }
    OK("游戏 PID: %d", pid);

    int total_ok = 0, total_fail = 0;

    /* 1. libtersafe.so */
    uint64_t ts_base = wait_for_module(pid, "libtersafe.so", 20000);
    if (ts_base) {
        int ok = 0, fail = 0;
        for (size_t i = 0; i < TERSAFE_PATCH_COUNT; i++) {
            uint64_t addr = ts_base + kTersafePatches[i].offset;
            if (safe_write32(pid, addr, kTersafePatches[i].value, 3) == 0) ok++;
            else fail++;
        }
        OK("tersafe code: %d ok / %d fail", ok, fail);
        total_ok += ok; total_fail += fail;
    } else { WARN("libtersafe.so 未加载"); }

    /* 2. libtersafe.so BSS 段 — 40 个全局检测标记清零 */
    uint64_t bss_base = get_module_base(pid, "libtersafe.so:bss");
    if (bss_base) {
        int ok = 0, fail = 0;
        for (size_t i = 0; i < TERSAFE_BSS_COUNT; i++) {
            uint64_t addr = bss_base + kTersafeBssOffsets[i];
            if (safe_write32(pid, addr, 0, 3) == 0) ok++;
            else fail++;
        }
        OK("tersafe bss: %d ok / %d fail", ok, fail);
        total_ok += ok; total_fail += fail;
    }

    /* 3. libUE4.so 引擎检测 — 7 处 */
    uint64_t ue4_base = wait_for_module(pid, "libUE4.so", 20000);
    if (ue4_base) {
        /* 确保 so 完全加载完成后再补丁 */
        usleep(500000);
        int ok = 0;
        for (size_t i = 0; i < UE4_PATCH_COUNT; i++) {
            uint64_t addr = ue4_base + kUE4Patches[i].offset;
            if (safe_write32(pid, addr, kUE4Patches[i].value, 3) == 0) ok++;
        }
        OK("UE4: %d ok", ok);
        total_ok += ok;
    }
    OK("内存过检完成: %d ok / %d fail", total_ok, total_fail);
    return (total_fail > 15) ? -1 : 0;
}

/* ============= 全局执行流程 ============= */
static int do_prepare(void) {
    /* 伪装 forge 进程名为内核线程，规避进程扫描 */
    prctl(PR_SET_NAME, "[kworker/u:0]", 0, 0, 0);
    protect_devmode();
    kill_suspicious_procs();
    block_tdm_reporting();  /* ← 新增: iptables 阻断上报 */
    clean_virt_traces();
    stop_game();
    sleep(2);
    int n = clean_all_ac_files();
    OK("清理文件: %d 个", n);
    restore_dirs();
    spoof_properties();
    protect_devmode();
    return 0;
}

static int do_launch(void) {
    do_prepare();
    start_logcat();
    /* 启动反作弊行为监控（后台，日志追加写入） */
    system("pkill -f forge_monitor 2>/dev/null; "
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
        inject_hook(pid);
    }
    /* hijack 模式下 libforgehook.so 已随 Qimei 自动加载, ptrace 注入是兜底 */
    int rc = patch_game_process();
    if (rc == 0) {
        pid = get_pid_by_name(TARGET_PKG);
        if (pid) hide_injection_from_maps(pid);
    }
    if (pid) {
        unlink(APP_DATA "/files/GPMSDK.mmap3");
        unlink(APP_DATA "/shared_prefs/GCloudCoreSP.xml");
        unlink(APP_DATA "/files/tdm_track.dat");
        unlink(APP_DATA "/shared_prefs/qm_global_sp.xml");
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
            while (1) {
                sleep(5);  /* 5s 间隔：快速响应 ace_shell_db.dat.tmp 等重建文件 */
                pid_t cp = get_pid_by_name(TARGET_PKG);
                if (cp <= 0) _exit(0);
                unlink(APP_DATA "/files/GPMSDK.mmap3");
                unlink(APP_DATA "/shared_prefs/GCloudCoreSP.xml");
                unlink(APP_DATA "/files/tdm_track.dat");
                unlink(APP_DATA "/shared_prefs/qm_global_sp.xml");
                for (int i = 0; kPurgeDirs[i]; i++) purge_dir_contents(kPurgeDirs[i]);
                for (int i = 0; kPreciseDeleteFiles[i]; i++) unlink(kPreciseDeleteFiles[i]);
                for (int i = 0; kExtraDeleteFiles[i]; i++) unlink(kExtraDeleteFiles[i]);
                DIR *d = opendir(kQmDir);
                if (d) {
                    struct dirent *ent;
                    while ((ent = readdir(d)) != NULL) {
                        if (match_qm_prefix(ent->d_name)) {
                            char full[4096]; snprintf(full, sizeof(full), "%s/%s", kQmDir, ent->d_name); unlink(full);
                        }
                    }
                    closedir(d);
                }
                for (int i = 0; kScanDirs[i]; i++)
                    for (int j = 0; kPatternSubstrings[j]; j++)
                        delete_matching(kScanDirs[i], kPatternSubstrings[j]);

                /* 每5秒回读关键补丁：若 TerSafe 已还原则立刻重写，日志可见是否发生 */
                {
                    pid_t vp2 = get_pid_by_name(TARGET_PKG);
                    uint64_t ts2 = vp2 > 0 ? get_module_base(vp2, "libtersafe.so") : 0;
                    if (ts2) {
                        static const struct { uint64_t off; uint32_t exp; } kChk[] = {
                                {0x419FDC, 0xD2800000},
                                {0x419FE0, 0xD65F03C0},
                                {0x2E7810, 0xD65F03C0},
                                {0x2F29D0, 0xD65F03C0},
                                {0x320D78, 0xD65F03C0},
                                {0x3233B8, 0xD65F03C0},
                            };
                            for (int ci = 0; ci < 6; ci++) {
                            uint32_t cur = 0;
                            if (mem_read32(vp2, ts2 + kChk[ci].off, &cur) == 0
                                && cur != kChk[ci].exp) {
                                WARN("patch reverted off=0x%llx cur=0x%08x — repatch",
                                     (unsigned long long)kChk[ci].off, cur);
                                safe_write32(vp2, ts2 + kChk[ci].off, kChk[ci].exp, 3);
                            }
                        }
                    }
                }
            }
        }
        /* 回收中间进程，避免僵尸 */
        if (mid > 0) waitpid(mid, NULL, 0);
    }
    return rc;
}

/* ============= TCP JSON 控制接口 =============
 * 手机端 app/adb forward 连接 cloud phone 的 9510 端口
 * 协议: 文本行, 以 \n 结尾
 * 命令: ping / prepare / launch / patch / stop / status / clean / spoof
 * 响应: JSON 单行
 */
static int handle_command(const char *req, char *resp, size_t resp_sz) {
    if (strncmp(req, "ping", 4) == 0) {
        snprintf(resp, resp_sz,
            "{\"status\":\"ok\",\"version\":\"" FORGE_VERSION "\"}");
    } else if (strncmp(req, "prepare", 7) == 0) {
        if (getuid() != 0) {
            snprintf(resp, resp_sz, "{\"status\":\"err\",\"msg\":\"need root\"}");
        } else {
            do_prepare();
            snprintf(resp, resp_sz, "{\"status\":\"ok\",\"msg\":\"prepare done\"}");
        }
    } else if (strncmp(req, "launch", 6) == 0) {
        if (getuid() != 0) {
            snprintf(resp, resp_sz, "{\"status\":\"err\",\"msg\":\"need root\"}");
        } else {
            int rc = do_launch();
            snprintf(resp, resp_sz, "{\"status\":\"%s\",\"msg\":\"launch %s\"}",
                rc == 0 ? "ok" : "partial",
                rc == 0 ? "done" : "some patches failed");
        }
    } else if (strncmp(req, "patch", 5) == 0) {
        int rc = patch_game_process();
        snprintf(resp, resp_sz, "{\"status\":\"%s\",\"msg\":\"patch %s\"}",
            rc == 0 ? "ok" : "partial",
            rc == 0 ? "done" : "some patches failed");
    } else if (strncmp(req, "stop", 4) == 0) {
        stop_game();
        snprintf(resp, resp_sz, "{\"status\":\"ok\",\"msg\":\"game stopped\"}");
    } else if (strncmp(req, "status", 6) == 0) {
        int running = target_is_running();
        pid_t pid = running ? get_pid_by_name(TARGET_PKG) : 0;
        snprintf(resp, resp_sz,
            "{\"status\":\"ok\",\"game_running\":%s,\"pid\":%d,\"uid\":%d}",
            running ? "true" : "false", pid, getuid());
    } else if (strncmp(req, "clean", 5) == 0) {
        int n = clean_all_ac_files();
        snprintf(resp, resp_sz, "{\"status\":\"ok\",\"cleaned\":%d}", n);
    } else if (strncmp(req, "spoof", 5) == 0) {
        spoof_properties();
        snprintf(resp, resp_sz, "{\"status\":\"ok\",\"msg\":\"props spoofed\"}");
    } else {
        snprintf(resp, resp_sz,
            "{\"status\":\"ok\",\"cmds\":[\"ping\",\"prepare\",\"launch\","
            "\"patch\",\"stop\",\"status\",\"clean\",\"spoof\"]}");
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

    while (1) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int cfd = accept(fd, (struct sockaddr*)&cli, &cli_len);
        if (cfd < 0) continue;

        char buf[4096] = {0};
        ssize_t n = recv(cfd, buf, sizeof(buf)-1, 0);
        if (n > 0) {
            buf[n] = 0;
            char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
            nl = strchr(buf, '\r'); if (nl) *nl = 0;

            char resp[4096];
            handle_command(buf, resp, sizeof(resp));
            send(cfd, resp, strlen(resp), 0);
        }
        close(cfd);
    }
    close(fd);
    return 0;
}

/* ============= main ============= */
static void print_usage(const char *prog) {
    fprintf(stderr,
        "DeltaForge v" FORGE_VERSION " — 三角洲行动云手机过检测核心\n"
        "用法: %s [选项]\n"
        "  -d    daemon/TCP 服务器模式 (端口 %d)\n"
        "  -p    一次性 prepare (清理+伪装+属性, 不启动游戏)\n"
        "  -l    一次性 launch (prepare + 启动游戏 + 内存补丁)\n"
        "  -m    仅内存补丁 (游戏必须已在运行)\n"
        "  -s    查询游戏运行状态\n"
        "  -c    仅清理反作弊文件\n"
        "  -x    仅伪装系统属性\n"
        "  -v    详细日志\n"
        "  -h    显示帮助\n",
        prog, CTRL_PORT);
}

int main(int argc, char **argv) {
    disguise_self();
    srand((unsigned int)(time(NULL) ^ (unsigned long)getpid()));

    int daemon_mode = 0, flag_prep = 0, flag_launch = 0, flag_patch = 0,
        flag_status = 0, flag_clean = 0, flag_spoof = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) g_verbose = 1;
        else if (!strcmp(argv[i], "-d")) daemon_mode = 1;
        else if (!strcmp(argv[i], "-p")) flag_prep = 1;
        else if (!strcmp(argv[i], "-l")) flag_launch = 1;
        else if (!strcmp(argv[i], "-m")) flag_patch = 1;
        else if (!strcmp(argv[i], "-s")) flag_status = 1;
        else if (!strcmp(argv[i], "-c")) flag_clean = 1;
        else if (!strcmp(argv[i], "-x")) flag_spoof = 1;
        else if (!strcmp(argv[i], "-h")) { print_usage(argv[0]); return 0; }
    }

    if (daemon_mode) {
        if (getuid() != 0) { ERR("daemon 模式需要 root 权限"); return 1; }
        g_logfile = fopen(FORGE_LOG, "a");
        OK("DeltaForge daemon v" FORGE_VERSION " 启动");
        return run_tcp_server();
    }

    if (getuid() != 0) { ERR("需要 root 权限"); return 1; }

    g_logfile = fopen(FORGE_LOG, "a");

    if (flag_launch) { return do_launch(); }
    if (flag_prep)   { do_prepare(); return 0; }
    if (flag_patch)  { return patch_game_process(); }
    if (flag_status) {
        int r = target_is_running();
        printf("game_running=%d pid=%d\n", r, r ? get_pid_by_name(TARGET_PKG) : 0);
        return 0;
    }
    if (flag_clean) { int n = clean_all_ac_files(); OK("cleaned %d files", n); return 0; }
    if (flag_spoof) { spoof_properties(); return 0; }

    /* 无参数 = 默认一次性 launch */
    do_prepare();
    start_game();
    patch_game_process();
    return 0;
}
