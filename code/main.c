/*
 * File: main.c
 * Description: The clean, minimal entry point of the L2 Raw Transfer application. 
 * It initializes all subsystems, reads user input, enforces the 60 FPS UI refresh rate, 
 * and delegates the protocol state processing to the sender and receiver engines.
 */

#include "protocol.h"
#include "system_utils.h"
#include "network_core.h"
#include "file_browser.h"
#include "ui_render.h"
#include "sender_engine.h"
#include "receiver_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <ncurses.h>

// Global application state context
AppContext ctx;

// Utility to clean up context memory after a transfer finishes or aborts
static void reset_transfer_context(AppContext *ctx) {
    if (ctx->bitmap != NULL) { 
        free(ctx->bitmap); 
        ctx->bitmap = NULL; 
    }
    if (ctx->file_fd >= 0) { 
        close(ctx->file_fd); 
        ctx->file_fd = -1; 
    }
    if (ctx->file_map != NULL && ctx->file_map != MAP_FAILED) { 
        munmap(ctx->file_map, ctx->total_bytes); 
        ctx->file_map = NULL; 
    }
    if (strlen(ctx->temp_tar_path) > 0) { 
        unlink(ctx->temp_tar_path); 
        ctx->temp_tar_path[0] = '\0'; 
    }
    
    ctx->target_path[0] = '\0';
    ctx->processed_bytes = 0; 
    ctx->sequence = 1; 
    ctx->total_bytes = 1; 
    ctx->total_fragments = 0;
    ctx->state = STATE_IDLE;
    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Ready. [R] Receive | [I] Send | [Q] Quit");
}

// Routes keyboard inputs depending on the current application state
static void handle_user_input(int ch) {
    if (ch == 'q' || ch == 'Q') {
        ctx.running = 0;
        return;
    }

    if (ctx.state == STATE_SELECT_INTERFACE) {
        if ((ch == KEY_UP || ch == 'k' || ch == 'K') && ctx.current_selection > 0) {
            ctx.current_selection--;
        } else if ((ch == KEY_DOWN || ch == 'j' || ch == 'J') && ctx.current_selection < ctx.interface_count - 1) {
            ctx.current_selection++;
        } else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) { 
            snprintf(ctx.active_interface, IFNAMSIZ, "%s", ctx.interface_list[ctx.current_selection]);
            if (setup_network(&ctx) == 0) {
                ctx.state = STATE_IDLE;
                snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Ready. [R] Receive | [I] Send | [Q] Quit");
            } else {
                ctx.state = STATE_ERROR;
                snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Network initialization error.");
            }
        }
    } 
    else if (ctx.state == STATE_IDLE) {
        if (ch == 'r' || ch == 'R') {
            ctx.state = STATE_RECEIVER_WAITING_PING;
            snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Listening on %s...", ctx.active_interface);
        } else if (ch == 'i' || ch == 'I') {
            ctx.state = STATE_BROWSE_FILES;
            load_directory(&ctx);
            ctx.browser_sel = 0; 
            ctx.scroll_offset = 0;
            snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Select file or folder to send.");
        }
    } 
    else if (ctx.state == STATE_BROWSE_FILES) {
        if (ch == KEY_UP && ctx.browser_sel > 0) ctx.browser_sel--;
        else if (ch == KEY_DOWN && ctx.browser_sel < ctx.entry_count - 1) ctx.browser_sel++;
        else if (ch == 27 || ch == 'b' || ch == 'B') { // ESC or 'b'
            ctx.state = STATE_IDLE;
            snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Ready. [R] Receive | [I] Send | [Q] Quit");
        }
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 's' || ch == 'S') {
            FileEntry *sel_entry = &ctx.dir_entries[ctx.browser_sel];
            
            // Enter directory
            if (sel_entry->is_dir && ch != 's' && ch != 'S') {
                char new_path[4354], resolved_path[4096];
                snprintf(new_path, sizeof(new_path), "%s/%s", ctx.current_dir, sel_entry->name);
                realpath(new_path, resolved_path); 
                snprintf(ctx.current_dir, sizeof(ctx.current_dir), "%s", resolved_path);
                load_directory(&ctx);
                ctx.browser_sel = 0; 
                ctx.scroll_offset = 0;
            } 
            // Select file/folder for transfer
            else if (strcmp(sel_entry->name, "..") != 0) {
                snprintf(ctx.target_path, sizeof(ctx.target_path), "%s/%s", ctx.current_dir, sel_entry->name);
                ctx.is_dir_transfer = sel_entry->is_dir;
                
                char *path_copy = strdup(ctx.target_path);
                strncpy(ctx.original_filename, basename(path_copy), sizeof(ctx.original_filename) - 1);
                free(path_copy);

                if (ctx.is_dir_transfer) {
                    ctx.state = STATE_SENDER_ARCHIVING;
                    snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Compressing folder (safe mode)...");
                } else {
                    ctx.file_fd = open(ctx.target_path, O_RDONLY);
                    if (ctx.file_fd < 0) {
                        ctx.state = STATE_ERROR;
                        snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Error: Cannot open '%s'.", ctx.target_path);
                    } else {
                        ctx.total_bytes = lseek(ctx.file_fd, 0, SEEK_END); 
                        lseek(ctx.file_fd, 0, SEEK_SET);               
                        ctx.state = STATE_SENDER_SENDING_PING;
                        snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Searching for receiver...");
                    }
                }
            }
        }
        
        // Auto-scroll logic for UI
        if (ctx.browser_sel < ctx.scroll_offset) ctx.scroll_offset = ctx.browser_sel;
        if (ctx.browser_sel >= ctx.scroll_offset + 10) ctx.scroll_offset = ctx.browser_sel - 9;
    } 
    else if (ctx.state == STATE_DONE || ctx.state == STATE_ERROR) {
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 'r' || ch == 'i') {
            reset_transfer_context(&ctx);
        }
    }
}

int main() {
    // 1. Initialize Global Context
    memset(&ctx, 0, sizeof(AppContext));
    ctx.running = 1;
    ctx.state = STATE_SELECT_INTERFACE;
    ctx.file_fd = -1;
    ctx.local_mtu = 1500; 
    ctx.original_mtu = 1500;
    ctx.negotiated_mtu = 1500; 
    ctx.neg_payload_size = 1400;
    snprintf(ctx.status_msg, sizeof(ctx.status_msg), "Use arrow keys and ENTER.");

    // 2. Setup System Hooks
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    getcwd(ctx.current_dir, sizeof(ctx.current_dir));

    // 3. Initialize Subsystems
    sender_engine_init();
    receiver_engine_init();
    init_tui();
    discover_interfaces(&ctx);

    long long last_draw_time = 0;

    // 4. Main Event Loop
    while (ctx.running && !g_shutdown_requested) {
        // Read non-blocking input
        int ch = getch();
        if (ch != ERR) {
            handle_user_input(ch);
        }

        // Delegate network logic to state machines
        sender_engine_tick(&ctx);
        receiver_engine_tick(&ctx);

        // Throttle UI rendering to ~60 FPS
        long long now = current_time_ms();
        if (now - last_draw_time >= 16) { 
            draw_interface(&ctx);
            last_draw_time = now; 
        }

        // Yield CPU to save power if not actively transferring huge blocks of data
        if (ctx.state != STATE_SENDER_TRANSFERRING && 
            ctx.state != STATE_RECEIVER_RECEIVING && 
            ctx.state != STATE_SENDER_WAITING_NACK) {
            usleep(16000); 
        }
    }

    // 5. Global Cleanup
    if (strlen(ctx.temp_tar_path) > 0) unlink(ctx.temp_tar_path);
    
    if (ctx.sock_fd >= 0 && ctx.local_mtu != ctx.original_mtu) {
        struct ifreq ifr_restore;
        memset(&ifr_restore, 0, sizeof(ifr_restore));
        snprintf(ifr_restore.ifr_name, IFNAMSIZ, "%s", ctx.active_interface);
        ioctl(ctx.sock_fd, SIOCSIFMTU, &ifr_restore);
    }

    if (ctx.file_map != NULL && ctx.file_map != MAP_FAILED) munmap(ctx.file_map, ctx.total_bytes); 
    if (ctx.file_fd >= 0) close(ctx.file_fd);
    if (ctx.sock_fd >= 0) close(ctx.sock_fd);
    if (ctx.bitmap != NULL) free(ctx.bitmap);
    
    cleanup_tui();
    
    return 0;
}
