/*
 * File: ui_render.h
 * Description: Declarations for initializing, drawing, and cleaning up the Ncurses UI.
 */

#ifndef UI_RENDER_H
#define UI_RENDER_H

#include "protocol.h"

void init_tui(void);
void cleanup_tui(void);
void draw_interface(AppContext *ctx);

#endif // UI_RENDER_H