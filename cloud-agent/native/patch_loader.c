// patch_loader.c — TASK-06: 极简 JSON 解析，无外部依赖
// 格式: { "build_id":"hex", "tersafe_patches":[{"offset":"0xN","value":"0xN","expected":"0xN"},...],
//          "tersafe_bss":["0xN",...], "ue4_patches":[...] }
#include "patch_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define PL_MAX_ENTRIES 256
#define PL_MAX_FILE    65536

/* 跳过空白 */
static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* 解析 "key" 并跳到 : 后，失败返回 NULL */
static const char *find_key(const char *json, const char *key) {
    size_t klen = strlen(key);
    const char *p = json;
    while (*p) {
        const char *q = strstr(p, key);
        if (!q) return NULL;
        /* check surrounding quotes */
        if (q > json && *(q-1) == '"') {
            const char *after = q + klen;
            if (*after == '"') {
                after = skip_ws(after + 1);
                if (*after == ':') return skip_ws(after + 1);
            }
        }
        p = q + 1;
    }
    return NULL;
}

/* 从 JSON 字符串提取 hex uint64_t，支持 "0xNN" 和 "NN" */
static int parse_hex64(const char *p, uint64_t *out) {
    p = skip_ws(p);
    if (*p == '"') p++;
    if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) p += 2;
    char *end;
    errno = 0;
    *out = (uint64_t)strtoull(p, &end, 16);
    return (end > p && errno == 0);
}

/* 读取 JSON 字符串值 (双引号内) 到 dest，返回 1 = 成功 */
static int read_str_value(const char *p, char *dest, size_t dest_sz) {
    p = skip_ws(p);
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < dest_sz) dest[i++] = *p++;
    dest[i] = '\0';
    return 1;
}

/* 解析一个 patch 数组 [{offset:X,value:Y},...] */
static int parse_patch_array(const char *start,
                              patch_entry_t *out, int max_out) {
    const char *p = skip_ws(start);
    if (*p != '[') return 0;
    p++;
    int count = 0;
    while (count < max_out) {
        p = skip_ws(p);
        if (*p == ']') break;
        if (*p != '{') { p++; continue; }
        p++;
        uint64_t off = 0, val = 0, expected = 0;
        int got_off = 0, got_val = 0, got_expected = 0;
        while (*p && *p != '}') {
            p = skip_ws(p);
            if (*p == '"') {
                const char *key_start = p + 1;
                const char *key_end   = strchr(key_start, '"');
                if (!key_end) break;
                size_t kl = (size_t)(key_end - key_start);
                p = skip_ws(key_end + 1);
                if (*p == ':') p = skip_ws(p + 1);
                if (kl == 6 && memcmp(key_start, "offset", 6) == 0) {
                    if (parse_hex64(p, &off)) got_off = 1;
                } else if (kl == 5 && memcmp(key_start, "value", 5) == 0) {
                    if (parse_hex64(p, &val)) got_val = 1;
                } else if (kl == 8 && memcmp(key_start, "expected", 8) == 0) {
                    if (parse_hex64(p, &expected)) got_expected = 1;
                }
                /* skip to next , or } */
                while (*p && *p != ',' && *p != '}') p++;
                if (*p == ',') p++;
            } else {
                p++;
            }
        }
        if (got_off && got_val && val <= UINT32_MAX) {
            out[count].offset = off;
            out[count].value  = (uint32_t)val;
            out[count].expected = (uint32_t)expected;
            out[count].has_expected = got_expected && expected <= UINT32_MAX;
            count++;
        }
        p = skip_ws(p);
        if (*p == '}') p++;
        p = skip_ws(p);
        if (*p == ',') p++;
    }
    return count;
}

/* 解析 uint64 数组 ["0xN", ...] */
static int parse_u64_array(const char *start, uint64_t *out, int max_out) {
    const char *p = skip_ws(start);
    if (*p != '[') return 0;
    p++;
    int count = 0;
    while (count < max_out) {
        p = skip_ws(p);
        if (*p == ']') break;
        uint64_t v = 0;
        if (parse_hex64(p, &v)) { out[count++] = v; }
        /* skip to next , or ] */
        while (*p && *p != ',' && *p != ']') p++;
        if (*p == ',') p++;
    }
    return count;
}

int patch_loader_load(const char *json_path, patch_table_t *out) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen(json_path, "r");
    if (!f) return 0;

    char *buf = (char *)malloc(PL_MAX_FILE + 1);
    if (!buf) { fclose(f); return 0; }
    size_t n = fread(buf, 1, PL_MAX_FILE, f);
    fclose(f);
    if (n == 0) { free(buf); return 0; }
    buf[n] = '\0';

    /* build_id */
    const char *p = find_key(buf, "build_id");
    if (p) read_str_value(p, out->build_id, sizeof(out->build_id));
    p = find_key(buf, "ue4_build_id");
    if (p) read_str_value(p, out->ue4_build_id, sizeof(out->ue4_build_id));

    /* tersafe_patches */
    p = find_key(buf, "tersafe_patches");
    if (p) {
        out->tersafe_patches = (patch_entry_t *)malloc(
            sizeof(patch_entry_t) * PL_MAX_ENTRIES);
        if (out->tersafe_patches)
            out->tersafe_count = parse_patch_array(p, out->tersafe_patches, PL_MAX_ENTRIES);
    }

    /* tersafe_bss */
    p = find_key(buf, "tersafe_bss");
    if (p) {
        out->tersafe_bss = (uint64_t *)malloc(sizeof(uint64_t) * PL_MAX_ENTRIES);
        if (out->tersafe_bss)
            out->bss_count = parse_u64_array(p, out->tersafe_bss, PL_MAX_ENTRIES);
    }

    /* ue4_patches */
    p = find_key(buf, "ue4_patches");
    if (p) {
        out->ue4_patches = (patch_entry_t *)malloc(
            sizeof(patch_entry_t) * PL_MAX_ENTRIES);
        if (out->ue4_patches)
            out->ue4_count = parse_patch_array(p, out->ue4_patches, PL_MAX_ENTRIES);
    }

    free(buf);
    int ok = out->tersafe_count > 0 || out->bss_count > 0 || out->ue4_count > 0;
    if (!ok) patch_loader_free(out);
    return ok;
}

void patch_loader_free(patch_table_t *t) {
    if (!t) return;
    free(t->tersafe_patches); t->tersafe_patches = NULL;
    free(t->tersafe_bss);     t->tersafe_bss     = NULL;
    free(t->ue4_patches);     t->ue4_patches     = NULL;
    t->tersafe_count = t->bss_count = t->ue4_count = 0;
    t->build_id[0] = '\0';
    t->ue4_build_id[0] = '\0';
}
