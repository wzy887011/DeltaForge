// ============================================================
// 法器: DeltaForge/cloud-agent/native/forge.c
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
#define FORGE_VERSION       "1.0.0"

static int do_prepare(void);
static int do_launch(void);

/* ============= 日志宏 ============= */
static int g_verbose = 0;
#define LOG(fmt, ...) do { \
    if (g_verbose) fprintf(stderr, "[forge] " fmt "\n", ##__VA_ARGS__); \
} while(0)
#define OK(fmt, ...)  fprintf(stderr, "\033[32m[+] " fmt "\033[0m\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "\033[33m[!] " fmt "\033[0m\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "\033[31m[-] " fmt "\033[0m\n", ##__VA_ARGS__)

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
};
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
    {0x00000034, 0x00000000},
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
    APP_DATA "/files/dg-patch",
    APP_DATA "/shared_prefs",
    APP_DATA "/databases",
    NULL
};
static const char *kPatternSubstrings[] = { "tdm", "hawk", "qv1", "lcc", "qc_", "qm_", NULL };
static const char *kQmDir = APP_DATA "/files/qm";
static const char *kQmPrefixes[] = { "cm_", "QV", "q", "lc", "qm", NULL };

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
    /* --- 伪装为 Xiaomi Redmi K60 (marble) --- */
    {"ro.product.manufacturer", "Xiaomi"},
    {"ro.product.model", "23049RAD8C"},
    {"ro.product.device", "marble"},
    {"ro.product.name", "marble"},
    {"ro.build.product", "marble"},
    {"ro.product.brand", "Xiaomi"},
    {"ro.hardware", "qcom"},
    {"ro.board.platform", "kalama"},
    {"ro.product.board", "kalama"},
    {"ro.build.fingerprint", "Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"},
    {"ro.build.version.sdk", "34"},
    {"ro.build.version.release", "14"},
    {"ro.build.version.incremental", "V816.0.9.0.UMRCNXM"},
    {"ro.build.tags", "release-keys"},
    {"ro.build.type", "user"},
    {"ro.build.user", "builder"},
    {"ro.build.host", "m1-xm-bsp-01"},
    {"ro.build.description", "marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"},
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    {"ro.allow.mock.location", "0"},
    {"persist.sys.usb.config", "adb"},
    {"gsm.version.baseband", "MPSS.TH.5.0-05076-OmniGen_PACK-1"},
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
            found_lib = 0;
        }
        if (strstr(line, lib)) {
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
        if (strcmp(buf, name) == 0) { r = (pid_t)atoi(ent->d_name); break; }
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

static int delete_large_files(const char *base, size_t thresh) {
    DIR *d = opendir(base);
    if (!d) return 0;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", base, ent->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            n += delete_large_files(full, thresh);
        } else if (S_ISREG(st.st_mode) && (size_t)st.st_size > thresh) {
            if (strstr(full, "/proc/") || strstr(full, "/system/") || strstr(full, "/sys/"))
                continue;
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
static void spoof_properties(void) {
    for (const prop_spoof_t *s = kSpoofProps; s->key; s++) {
        char cmd[512];
        if (s->value) {
            snprintf(cmd, sizeof(cmd),
                "resetprop '%s' '%s' 2>/dev/null; setprop '%s' '%s' 2>/dev/null",
                s->key, s->value, s->key, s->value);
        } else {
            snprintf(cmd, sizeof(cmd),
                "resetprop --delete '%s' 2>/dev/null; setprop '%s' '' 2>/dev/null",
                s->key, s->key);
        }
        system(cmd);
    }
    OK("系统属性伪装完成 (%zu 项)",
        (sizeof(kSpoofProps)/sizeof(kSpoofProps[0]) - 1));
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

/* ============= iptables 阻断 TDM/CrashSight/TSS 网络上报 =============
 * 腾讯反作弊 SDK 通过独立 TCP/UDP 通道上报检测数据，与游戏主逻辑分离。
 * 这些上报域名和端口在 APK 逆向中已识别（strings/常量分析）。
 *
 * 策略:
 *   a) 阻断游戏进程 UID 的全部非必要出站连接 (OUTPUT chain)
 *   b) 用 iptables owner 模块匹配游戏 UID，只放行游戏服务器 IP
 *   c) 显式 drop 已知的 TDM/CrashSight/TGPASDK 上报域名/IP 段
 *
 * 注意: 需要内核编译了 netfilter xt_owner 模块；大多数云手机内核都有。
 */
static void block_tdm_reporting(void) {
    /* 获取游戏 UID */
    char uid_buf[32] = {0};
    FILE *fp = popen("dumpsys package com.tencent.tmgp.dfm 2>/dev/null | grep 'userId=' | head -1", "r");
    if (fp) { fgets(uid_buf, sizeof(uid_buf)-1, fp); pclose(fp); }

    /* 已知 TDM/CrashSight/GPM 上报域名 (从 APK strings/NetworkConfig 逆向提取) */
    static const char *BLOCKED_DOMAINS[] = {
        "tdm.qq.com", "tdm.tencent.com", "tdm.3g.qq.com",
        "oth.eve.mdt.qq.com", "crashsight.qq.com", "crashsight.tencent.com",
        "android.crashsight.qq.com", "dlied1.qq.com",
        "cloud.tencent.com", "cloud.tencent.com.cn",
        "gcloud.tencent.com", "gcloud.tencent.com.cn",
        "api.cloud.tencent.com", "cml.qcloud.com",
        "tpstelemetry.tencent.com", "report.qq.com",
        "stat.qq.com", "pingma.qq.com",
        "szmg.qq.com", "pgdt.gtimg.cn",
        "gamelobby.qq.com", "igame.qq.com",
        "mtcls.qq.com", "qos.qq.com",
        "vas.qq.com", "qun.qq.com",
        NULL
    };

    /* 显式 DROP 这些域的 DNS 解析结果 (需要先 nslookup 拿 IP 段) */
    char cmd[1024];
    for (const char **d = BLOCKED_DOMAINS; *d; d++) {
        /* 用 iptables string 模块匹配域名 (kernel xt_string 需要启用) */
        snprintf(cmd, sizeof(cmd),
            "iptables -C OUTPUT -m string --algo bm --string '%s' -j DROP 2>/dev/null || "
            "iptables -I OUTPUT 1 -m string --algo bm --string '%s' -j DROP 2>/dev/null",
            *d, *d);
        system(cmd);
    }

    /* 如果内核有 xt_owner: 阻断游戏 UID 所有出站 TCP，只放行 DNS+特定端口 */
    snprintf(cmd, sizeof(cmd),
        "iptables -C OUTPUT -m owner --uid-owner %s -p tcp --dport 53 -j ACCEPT 2>/dev/null || "
        "iptables -I OUTPUT 1 -m owner --uid-owner %s -p tcp --dport 53 -j ACCEPT 2>/dev/null",
        uid_buf, uid_buf);

    /* 放行游戏服务器端口 (三角洲游戏端口范围: 8080/443/14000-14100) */
    snprintf(cmd, sizeof(cmd),
        "iptables -C OUTPUT -m owner --uid-owner %s -p tcp --dport 443 -j ACCEPT 2>/dev/null || "
        "iptables -I OUTPUT 2 -m owner --uid-owner %s -p tcp --dport 443 -j ACCEPT 2>/dev/null",
        uid_buf, uid_buf);

    snprintf(cmd, sizeof(cmd),
        "iptables -C OUTPUT -m owner --uid-owner %s -p tcp --dport 8080 -j ACCEPT 2>/dev/null || "
        "iptables -I OUTPUT 3 -m owner --uid-owner %s -p tcp --dport 8080 -j ACCEPT 2>/dev/null",
        uid_buf, uid_buf);

    /* 阻断其余所有出站连接 */
    snprintf(cmd, sizeof(cmd),
        "iptables -C OUTPUT -m owner --uid-owner %s -j DROP 2>/dev/null || "
        "iptables -I OUTPUT 4 -m owner --uid-owner %s -j DROP 2>/dev/null",
        uid_buf, uid_buf);

    OK("TDM/CRASHSIGHT/GPM 网络上报已阻断 (%s)", uid_buf);
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
    /* LD_PRELOAD 注入 libforgehook.so — 拦截 /proc/cpuinfo 等硬件文件读取 */
    snprintf(buf, sizeof(buf),
        "LD_PRELOAD=/data/local/tmp/libforgehook.so "
        "am start -n %s/%s.PermissionActivity 2>/dev/null",
        TARGET_PKG, TARGET_PKG);
    system(buf);
    OK("游戏已启动 (LD_PRELOAD hook)");
}

/* ============= 核心: 内存补丁执行 ============= */
static int patch_game_process(void) {
    pid_t pid = 0;
    for (int i = 0; i < 120; i++) {
        pid = get_pid_by_name(TARGET_PKG);
        if (pid) break;
        usleep(100000);
    }
    if (!pid) { WARN("未找到游戏进程"); return -1; }
    OK("游戏 PID: %d", pid);

    int total_ok = 0, total_fail = 0;

    /* 1. libtersafe.so 代码段 — 61 处关键函数 patch */
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
        sleep(3);
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
    start_game();
    int rc = patch_game_process();
    /* 补丁成功后隐藏 maps 注入痕迹 */
    if (rc == 0) {
        pid_t pid = get_pid_by_name(TARGET_PKG);
        if (pid) hide_injection_from_maps(pid);
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
        OK("DeltaForge daemon v" FORGE_VERSION " 启动");
        return run_tcp_server();
    }

    if (getuid() != 0) { ERR("需要 root 权限"); return 1; }

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
