#include <stdio.h>
#include <string.h>

#include "../cloud-agent/native/patch_loader.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s PATCH_JSON\n", argv[0]);
        return 2;
    }

    patch_table_t table;
    if (!patch_loader_load(argv[1], &table)) {
        fprintf(stderr, "patch table load failed\n");
        return 1;
    }

    int ok = table.tersafe_count == 72
        && table.bss_count == 40
        && table.ue4_count == 0
        && strcmp(table.build_id,
            "d70d7926094ae39a46745c12ddcc1877641f82e8") == 0
        && strcmp(table.ue4_build_id,
            "8187ddb9edbc9d5201201ffd7b008df3bfe533db") == 0;
    for (int i = 0; i < table.tersafe_count; i++) {
        if (!table.tersafe_patches[i].has_expected) ok = 0;
    }

    printf("tersafe=%d bss=%d ue4=%d guarded=%s\n",
        table.tersafe_count, table.bss_count, table.ue4_count,
        ok ? "yes" : "no");
    patch_loader_free(&table);
    return ok ? 0 : 1;
}
