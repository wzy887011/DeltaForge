// patch_loader.h — TASK-06: 外置偏移表热更新
// forge 启动时读取 /data/local/tmp/forge_patches.json，
// 失败则回退内置静态表 kTersafePatches / kTersafeBssOffsets / kUE4Patches
#pragma once
#include <stdint.h>

typedef struct {
    uint64_t offset;
    uint32_t value;
} patch_entry_dyn_t;

typedef struct {
    patch_entry_dyn_t *tersafe_patches;
    int                tersafe_count;
    uint64_t          *tersafe_bss;
    int                bss_count;
    patch_entry_dyn_t *ue4_patches;
    int                ue4_count;
    char               build_id[128]; /* expected tersafe build-id, "" = skip */
} patch_table_t;

// 从 JSON 文件加载偏移表，成功返回 1，失败返回 0
int  patch_loader_load(const char *json_path, patch_table_t *out);
// 释放 patch_loader_load 分配的内存
void patch_loader_free(patch_table_t *t);
