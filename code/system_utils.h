/*
 * File: system_utils.h
 * Description: Declarations for utility functions like timing, secure command 
 * execution, and signal handling.
 */

#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <signal.h>

// Global flag to safely handle asynchronous signals like SIGINT (Ctrl+C)
extern volatile sig_atomic_t g_shutdown_requested;

void handle_signal(int sig);
long long current_time_ms();

// Safe execution to prevent Shell Injection
int execute_tar_safe(char *const args[]);

#endif // SYSTEM_UTILS_H