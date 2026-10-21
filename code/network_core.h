/*
 * File: network_core.h
 * Description: Declarations for network configuration and socket initialization.
 */

#ifndef NETWORK_CORE_H
#define NETWORK_CORE_H

#include "protocol.h"

void discover_interfaces(AppContext *ctx);
int setup_network(AppContext *ctx);

#endif // NETWORK_CORE_H