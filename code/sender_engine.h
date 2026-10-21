/*
 * File: sender_engine.h
 * Description: Declarations for the Sender state machine.
 */

#ifndef SENDER_ENGINE_H
#define SENDER_ENGINE_H

#include "protocol.h"

// Initializes static memory buffers used for batch transmission
void sender_engine_init(void);

// Processes one cycle of the sender state machine
void sender_engine_tick(AppContext *ctx);

#endif // SENDER_ENGINE_H