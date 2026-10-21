/*
 * File: ui_render.c
 * Description: Implementation of the Text User Interface using Ncurses. 
 * Reads the application state from AppContext and renders it to the terminal screen.
 */

#include "ui_render.h"
#include <ncurses.h>

void init_tui(void) {
    initscr();              // Start ncurses mode
    cbreak();               // Disable line buffering (pass chars immediately)
    noecho();               // Do not print typed characters
    keypad(stdscr, TRUE);   // Enable arrow keys
    nodelay(stdscr, TRUE);  // Make getch() non-blocking
    curs_set(0);            // Hide the blinking cursor
}

void cleanup_tui(void) {
    endwin();               // End ncurses mode and restore standard terminal
}

// Renders the UI based purely on the current state stored in AppContext.
// This decouple allows the main loop to handle logic without worrying about pixels.
void draw_interface(AppContext *ctx) {
    erase(); 
    box(stdscr, 0, 0);

    attron(A_BOLD);
    mvprintw(1, 2, " RAW L2 TRANSFER ");
    attroff(A_BOLD);
    mvprintw(2, 2, "---------------------------------------------");

    if (ctx->state == STATE_SELECT_INTERFACE) {
        mvprintw(4, 4, "Select network interface:");
        for (int i = 0; i < ctx->interface_count; i++) {
            if (i == ctx->current_selection) attron(A_REVERSE); 
            mvprintw(6 + i, 6, " %s %s ", i == ctx->current_selection ? ">" : " ", ctx->interface_list[i]);
            if (i == ctx->current_selection) attroff(A_REVERSE);
        }
    } 
    else if (ctx->state == STATE_BROWSE_FILES) {
        mvprintw(4, 4, "Dir: %s", ctx->current_dir);
        mvprintw(5, 4, "[ENTER] Enter/Send File | [S] Send Selected | [ESC] Back");
        
        // Scroll limit logic
        for (int i = 0; i < 10 && (ctx->scroll_offset + i) < ctx->entry_count; i++) {
            int idx = ctx->scroll_offset + i;
            if (idx == ctx->browser_sel) attron(A_REVERSE);
            mvprintw(7 + i, 6, " %s %s ", ctx->dir_entries[idx].is_dir ? "[DIR] " : "      ", ctx->dir_entries[idx].name);
            if (idx == ctx->browser_sel) attroff(A_REVERSE);
        }
    }
    else {
        mvprintw(4, 4, "Interface: %s | Network MTU: %d", ctx->active_interface, ctx->negotiated_mtu);
        mvprintw(5, 4, "Status: %s", ctx->status_msg);
        
        if (ctx->state != STATE_ERROR) {
            mvprintw(7, 4, "My MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
                     ctx->my_mac[0], ctx->my_mac[1], ctx->my_mac[2], 
                     ctx->my_mac[3], ctx->my_mac[4], ctx->my_mac[5]);
        }
        
        // Progress bar for active transfers
        if (ctx->state == STATE_SENDER_TRANSFERRING || ctx->state == STATE_RECEIVER_RECEIVING || 
            ctx->state == STATE_DONE || ctx->state == STATE_SENDER_WAITING_NACK || 
            ctx->state == STATE_RECEIVER_EXTRACTING) {
            
            mvprintw(8, 4, "Target MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
                     ctx->target_mac[0], ctx->target_mac[1], ctx->target_mac[2], 
                     ctx->target_mac[3], ctx->target_mac[4], ctx->target_mac[5]);
        
            int bar_width = 40;
            int filled = (ctx->total_bytes > 0) ? (ctx->processed_bytes * bar_width) / ctx->total_bytes : 0;
            if (filled > bar_width) filled = bar_width;
            
            mvprintw(10, 4, "[");
            for (int i = 0; i < bar_width; i++) addch(i < filled ? '#' : '-');
            printw("] %d%% (%llu/%llu bytes) %s", 
                   (ctx->total_bytes > 0) ? (int)((ctx->processed_bytes * 100) / ctx->total_bytes) : 0, 
                   (unsigned long long)ctx->processed_bytes, (unsigned long long)ctx->total_bytes, 
                   ctx->is_dir_transfer ? "[DIRECTORY]" : "[FILE]");
        }
    }
    refresh();
}