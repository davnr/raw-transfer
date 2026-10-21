/*
 * File: receiver_engine.h
 * Description: Declarations for the Receiver state machine.
 */

#ifndef RECEIVER_ENGINE_H
#define RECEIVER_ENGINE_H

#include "protocol.h"

// Initializes static memory buffers used for batch reception
void receiver_engine_init(void);

// Processes one cycle of the receiver state machine
void receiver_engine_tick(AppContext *ctx);

#endif // RECEIVER_ENGINE_H