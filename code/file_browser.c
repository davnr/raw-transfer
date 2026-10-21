/*
 * File: file_browser.c
 * Description: Implements directory loading via dirent.h, resolving file statistics
 * (to distinguish files from folders), and sorting them logically (folders on top).
 */

#include "file_browser.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Helper function to sort directories: folders first, then files alphabetically.
static int compare_entries(const void *a, const void *b) {
    FileEntry *e1 = (FileEntry *)a;
    FileEntry *e2 = (FileEntry *)b;
    
    // Always keep ".." at the top for easy backward navigation
    if (strcmp(e1->name, "..") == 0) return -1;
    if (strcmp(e2->name, "..") == 0) return 1;
    
    // Folders come before files
    if (e1->is_dir && !e2->is_dir) return -1;
    if (!e1->is_dir && e2->is_dir) return 1;
    
    // Alphabetical sort for same types
    return strcasecmp(e1->name, e2->name);
}

// Scans the folder specified in ctx->current_dir and populates ctx->dir_entries
void load_directory(AppContext *ctx) {
    ctx->entry_count = 0;
    struct dirent **namelist;
    
    // scandir automatically reads the folder and allocates the list
    int n = scandir(ctx->current_dir, &namelist, NULL, alphasort);
    if (n < 0) return;

    for (int i = 0; i < n; i++) {
        // Skip current directory pointer "."
        if (strcmp(namelist[i]->d_name, ".") == 0) {
            free(namelist[i]); 
            continue;
        }
        snprintf(ctx->dir_entries[ctx->entry_count].name, 256, "%s", namelist[i]->d_name);
        
        char full_path[4354];
        snprintf(full_path, sizeof(full_path), "%s/%s", ctx->current_dir, namelist[i]->d_name);        
        // Check if item is a directory using stat()
        struct stat st;
        if (stat(full_path, &st) == 0) {
            ctx->dir_entries[ctx->entry_count].is_dir = S_ISDIR(st.st_mode);
        } else {
            ctx->dir_entries[ctx->entry_count].is_dir = (namelist[i]->d_type == DT_DIR);
        }
        
        free(namelist[i]);
        ctx->entry_count++;
        
        if (ctx->entry_count >= MAX_DIR_ENTRIES) break;
    }
    free(namelist);
    
    // Apply the custom sort
    qsort(ctx->dir_entries, ctx->entry_count, sizeof(FileEntry), compare_entries);
}
