/*
 * File: protocol.h
 * Description: Contains all definitions, macros, protocol structures, 
 * and the global AppContext struct used to share state across modules.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <net/if.h>
#include <linux/if_packet.h>

// --- PROTOCOL CONSTANTS ---
#define CUSTOM_ETHERTYPE 0x88B5     // Custom ethertype to bypass standard TCP/IP stack
#define OP_PING 0                   // Sender looking for receiver
#define OP_PONG 1                   // Receiver accepting connection
#define OP_DATA 2                   // Data fragment
#define OP_NACK 3                   // Missing fragments requested by receiver
#define OP_DONE 4                   // Transfer completed

#define BATCH_SIZE 256              // Number of packets sent/received in a single batch
#define MAX_JUMBO_PAYLOAD 8950      // Max payload size for 9000 MTU Jumbo Frames
#define MAX_DIR_ENTRIES 1024        // Maximum items shown in the File Browser

// --- PROTOCOL STRUCTURES ---
// Note: __attribute__((packed)) prevents the compiler from adding empty bytes (padding).
// This ensures the struct maps exactly to the bytes sent over the network cable.

struct file_meta {
    uint8_t opcode;      
    uint32_t seq_num;    
    uint16_t data_size;  
    uint8_t is_eof;      
} __attribute__((packed));

struct handshake_info {
    uint64_t total_bytes;  
    uint16_t sender_mtu;   
    uint8_t is_dir;        
    char filename[256];    
} __attribute__((packed));

struct handshake_response {
    uint16_t negotiated_mtu;  
    uint32_t total_fragments; 
} __attribute__((packed));

struct custom_frame {
    unsigned char dest_mac[6];                 
    unsigned char src_mac[6];                  
    unsigned short ether_type;                 
    struct file_meta meta;                     
    unsigned char payload[MAX_JUMBO_PAYLOAD];  
} __attribute__((packed));

struct nack_payload {
    uint16_t count;          
    uint32_t sequences[349]; 
} __attribute__((packed));

// --- APPLICATION STATE MACHINE ---
typedef enum {
    STATE_SELECT_INTERFACE,
    STATE_IDLE,
    STATE_BROWSE_FILES,
    STATE_RECEIVER_WAITING_PING,
    STATE_RECEIVER_RECEIVING,
    STATE_RECEIVER_EXTRACTING, 
    STATE_SENDER_ARCHIVING,    
    STATE_SENDER_SENDING_PING,
    STATE_SENDER_WAITING_PONG,
    STATE_SENDER_TRANSFERRING,
    STATE_SENDER_WAITING_NACK, 
    STATE_DONE,
    STATE_ERROR
} AppState;

// --- FILE BROWSER STRUCTURE ---
typedef struct {
    char name[256];
    int is_dir;
} FileEntry;

// --- GLOBAL APPLICATION CONTEXT ---
// This struct prevents having functions with 20 parameters.
// It holds the entire state of the program.
typedef struct {
    int running;                     // 1 if app is running, 0 to exit
    AppState state;                  // Current state of the machine
    char status_msg[1024];            // Feedback message for the user

    // Network Interface Selection
    char interface_list[10][IFNAMSIZ];
    int interface_count;
    int current_selection;
    char active_interface[IFNAMSIZ];

    // File Browser State
    char current_dir[4096];
    FileEntry dir_entries[MAX_DIR_ENTRIES];
    int entry_count;
    int browser_sel;
    int scroll_offset;

    // Network State
    int sock_fd;
    unsigned char my_mac[6];
    unsigned char target_mac[6];
    struct sockaddr_ll sll;
    int local_mtu;
    int original_mtu;
    int negotiated_mtu;
    int neg_payload_size;

    // File Transfer State
    int file_fd;
    uint64_t total_bytes;
    uint64_t processed_bytes;
    uint32_t total_fragments;
    uint32_t sequence;
    uint8_t *bitmap;                 // Tracks which packets arrived (for NACK)
    uint8_t *file_map;               // Memory mapped file pointer

    char target_path[4354];          // Path of the file to send/receive
    char temp_tar_path[4354];        // Path of temporary archive (if directory)
    char original_filename[256];
    int is_dir_transfer;
} AppContext;

#endif // PROTOCOL_H
