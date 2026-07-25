#!/usr/bin/env python3
# ============================================================
# tools/crypt_gen.py — DeltaForge v7.1 字符串加密字节生成器
# 用法: python3 crypt_gen.py > crypt_strings.h
# 该头文件同时被 forge.c 和 libforgehook.c include
# ============================================================

import sys

CRYPT_KEY = 0x73

# ── 待加密字符串清单 ──────────────────────────────────────
# (变量名, 原文)
STRINGS = [
    # libforgehook 注入库标识
    ("forgehook",       "libforgehook"),
    ("forgehook_real",  "libtdmqimei_real.so"),
    ("qimei",           "libtdmqimei"),
    ("qimei_underscore","libqimei_"),
    ("forgehook_log",   "/data/local/tmp/forge_hook.log"),
    ("forge_log",       "/data/local/tmp/forge.log"),
    ("audit_log",       "/data/data/com.tencent.tmgp.dfm/files/forge_audit.log"),
    # shell 临时文件
    ("devshm_fh",       "/dev/shm/.fh"),
    ("devshm_ac",       "/dev/shm/.ac"),
    ("devshm_maps",     "maps_v7"),
    ("maps_path",       "/proc/self/maps"),
    # forge.c 模块名
    ("tersafe",         "libtersafe.so"),
    ("ue4",             "libUE4.so"),
    ("target_pkg",      "com.tencent.tmgp.dfm"),
    ("target_app_dir",  "/data/data/com.tencent.tmgp.dfm"),
    ("target_splash",   "com.epicgames.ue4.SplashActivity"),
    # forge.c 路径
    ("frg_log",         "/data/local/tmp/forge.log"),
    ("detect_log",      "/data/local/tmp/detect_now.log"),
    ("hook_so",         "/data/local/tmp/libforgehook.so"),
    ("injector_path",   "/data/local/tmp/injector"),
    ("ad_app",          "/data/app/"),
    ("ad_localtmp",     "/data/local/tmp/"),
    # forge.c 密钥/认证
    ("session_key",     "/data/local/tmp/.forge_key"),
    ("bss_cache",       "/data/local/tmp/forge_bss_map.json"),
    ("repair_log",      "/data/local/tmp/forge_repair.log"),
    # 诊断
    ("tombstone",       "/data/tombstones/"),
    ("fp_galaxy",       "samsung/beyond1qltezc/beyond1q"),
    ("cmd_stop",        "am force-stop"),
    ("cmd_killall",     "killall -9"),
]

# ── 生成 C 头文件 ──────────────────────────────────────────
def main():
    print("// ============================================================")
    print("// crypt_strings.h — DeltaForge v7.1 自动生成")
    print("// 生成工具: tools/crypt_gen.py")
    print(f"// XOR key: 0x{CRYPT_KEY:02X}")
    print("// 警告: 此文件为自动生成，不要手动编辑")
    print("// ============================================================")
    print("")
    print("#ifndef DELTAFORGE_CRYPT_STRINGS_H")
    print("#define DELTAFORGE_CRYPT_STRINGS_H")
    print("")
    print(f"#define CRYPT_KEY 0x{CRYPT_KEY:02X}")
    print("")
    print("// ── 运行时解密 helper ──────────────────────────────────────")
    print("// 在栈上解密，返回临时指针。调用方应在使用后立即消耗。")
    print("// 对于需要持久化的字符串，使用 CRYPT_STR_INIT 变体。")
    print("static inline const char *xstr(const unsigned char *e, int n) {")
    print("    static char _xb[256];")
    print("    if (n > 255) n = 255;")
    print("    for (int i = 0; i < n; i++) _xb[i] = (char)(e[i] ^ CRYPT_KEY);")
    print("    _xb[n] = 0;")
    print("    return _xb;")
    print("}")
    print("")
    print("// ── 长生命周期解密: 调用方提供缓冲区 ──────────────────────")
    print("static inline void xstr_buf(const unsigned char *e, int n, char *out) {")
    print("    for (int i = 0; i < n; i++) out[i] = (char)(e[i] ^ CRYPT_KEY);")
    print("    out[n] = 0;")
    print("}")
    print("")
    print("// ── 精确比较: 加密字符串 vs 明文，避免先解密的 temp buf 问题 ──")
    print("static inline int xstr_eq(const unsigned char *e, int n, const char *plain) {")
    print("    for (int i = 0; i < n; i++)")
    print("        if ((char)(e[i] ^ CRYPT_KEY) != plain[i]) return 0;")
    print("    return plain[n] == 0;")
    print("}")
    print("")
    print("// ── strstr 变体: 在明文中查找加密片段 ──")
    print("static inline int xstr_strstr(const char *haystack,")
    print("                                const unsigned char *needle_e, int n) {")
    print("    if (!haystack || n <= 0) return 0;")
    print("    int hl = (int)strlen(haystack);")
    print("    if (hl < n) return 0;")
    print("    for (int i = 0; i <= hl - n; i++) {")
    print("        int j;")
    print("        for (j = 0; j < n; j++)")
    print("            if ((char)(needle_e[j] ^ CRYPT_KEY) != haystack[i+j]) break;")
    print("        if (j == n) return 1;")
    print("    }")
    print("    return 0;")
    print("}")
    print("")

    # ── 生成加密字节数组 ────────────────────────────────────
    for varname, orig in STRINGS:
        enc = [f"0x{(ord(c) ^ CRYPT_KEY):02X}" for c in orig]
        enc_str = ", ".join(enc)
        print(f"// \"{orig}\"")
        print(f"static const unsigned char _E_{varname}[{len(orig)}] = {{{enc_str}}};")
        print(f"#define C_{varname} (xstr(_E_{varname}, {len(orig)}))")
        print("")

    print("#endif // DELTAFORGE_CRYPT_STRINGS_H")
    return 0

if __name__ == "__main__":
    sys.exit(main())
