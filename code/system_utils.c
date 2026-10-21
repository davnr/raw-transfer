/*
 * File: system_utils.c
 * Description: Implementation of system-level utilities. Includes a secure alternative 
 * to system() for executing tar commands without invoking the vulnerable shell interpreter.
 */

#include "system_utils.h"
#include <sys/time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

volatile sig_atomic_t g_shutdown_requested = 0;

void handle_signal(int sig) {
    (void)sig; // Suppress unused parameter warning
    g_shutdown_requested = 1;
}

long long current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

// Executes a command bypassing the shell to prevent Shell Injection.
// If we used system("tar -cf file.tar user_input"), a malicious user_input 
// like "a; rm -rf /" would delete the disk. Using fork/execvp solves this.
int execute_tar_safe(char *const args[]) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: executes the binary directly. 
        // execvp replaces the child's memory space with the new program.
        execvp("tar", args);
        exit(127); // Reached only if execvp fails (e.g., 'tar' not found)
    } else if (pid > 0) {
        // Parent process: waits for the child to finish
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    return -1; // fork() failed
}