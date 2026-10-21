/*
 * File: receiver_engine.c
 * Description: Implements the Data Link layer receiving logic. It handles
 * incoming connection requests, Zero-Copy file writing via memory mapping (mmap),
 * identifying missing fragments (NACK generation), and directory extraction.
 */

#include "receiver_engine.h"
#include "system_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>

// Static buffers for high-performance batch reception (recvmmsg)
static struct mmsghdr rx_msgs[BATCH_SIZE];
static struct iovec rx_iov[BATCH_SIZE];
static struct custom_frame rx_frames[BATCH_SIZE];
static struct sockaddr_ll remote_sll_arr[BATCH_SIZE];

void receiver_engine_init(void) {
    memset(rx_msgs, 0, sizeof(rx_msgs));
    memset(rx_iov, 0, sizeof(rx_iov));
    memset(rx_frames, 0, sizeof(rx_frames));
    memset(remote_sll_arr, 0, sizeof(remote_sll_arr));

    for (int i = 0; i < BATCH_SIZE; i++) {
        rx_iov[i].iov_base = &rx_frames[i];
        rx_iov[i].iov_len = sizeof(struct custom_frame);
        
        rx_msgs[i].msg_hdr.msg_iov = &rx_iov[i];
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
        rx_msgs[i].msg_hdr.msg_name = &remote_sll_arr[i];
        rx_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
    }
}

void receiver_engine_tick(AppContext *ctx) {
    // ---------------------------------------------------------
    // STATE: WAITING PING / RECEIVING DATA
    // ---------------------------------------------------------
    if (ctx->state == STATE_RECEIVER_WAITING_PING || ctx->state == STATE_RECEIVER_RECEIVING) {
        
        while (1) {
            // Read incoming frames in batches to heavily reduce CPU usage
            int vlen = recvmmsg(ctx->sock_fd, rx_msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
            if (vlen < 0) break; // Queue empty
            
            for (int i = 0; i < vlen; i++) {
                struct custom_frame *rx_frame = &rx_frames[i];
                socklen_t sll_len = rx_msgs[i].msg_hdr.msg_namelen;
                
                // Ensure the packet is part of our custom protocol
                if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                    
                    // --- HANDSHAKE: PING RECEIVED ---
                    if (ctx->state == STATE_RECEIVER_WAITING_PING && rx_frame->meta.opcode == OP_PING) {
                        memcpy(ctx->target_mac, rx_frame->src_mac, 6);
                        
                        struct handshake_info *hi = (struct handshake_info *)rx_frame->payload;
                        ctx->total_bytes = hi->total_bytes;
                        uint16_t sender_mtu = ntohs(hi->sender_mtu);
                        ctx->is_dir_transfer = hi->is_dir;
                        strncpy(ctx->original_filename, hi->filename, sizeof(ctx->original_filename) - 1);
                        
                        if (ctx->is_dir_transfer) {
                            snprintf(ctx->target_path, sizeof(ctx->target_path), "recv_%s.tar", ctx->original_filename);
                        } else {
                            snprintf(ctx->target_path, sizeof(ctx->target_path), "recv_%s", ctx->original_filename);
                        }
                        
                        // Determine the safest MTU (minimum between sender and receiver)
                        ctx->negotiated_mtu = (sender_mtu < ctx->local_mtu) ? sender_mtu : ctx->local_mtu;
                        ctx->neg_payload_size = ctx->negotiated_mtu - sizeof(struct file_meta);
                        if (ctx->neg_payload_size > MAX_JUMBO_PAYLOAD) {
                            ctx->neg_payload_size = MAX_JUMBO_PAYLOAD;
                        }
                        
                        // Calculate fragments and allocate memory mapping
                        ctx->total_fragments = (ctx->total_bytes + ctx->neg_payload_size - 1) / ctx->neg_payload_size;
                        ctx->bitmap = calloc(ctx->total_fragments + 1, sizeof(uint8_t));
                        
                        // Pre-allocate file size and map it to RAM
                        ctx->file_fd = open(ctx->target_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
                        ftruncate(ctx->file_fd, ctx->total_bytes); 
                        ctx->file_map = mmap(NULL, ctx->total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->file_fd, 0);
                        
                        // Formulate PONG response
                        struct custom_frame tx_frame;
                        memset(&tx_frame, 0, sizeof(tx_frame));
                        memcpy(tx_frame.dest_mac, ctx->target_mac, 6);
                        memcpy(tx_frame.src_mac, ctx->my_mac, 6);
                        tx_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                        tx_frame.meta.opcode = OP_PONG;
                        
                        struct handshake_response hr;
                        hr.negotiated_mtu = htons(ctx->negotiated_mtu);
                        hr.total_fragments = htonl(ctx->total_fragments);
                        memcpy(tx_frame.payload, &hr, sizeof(struct handshake_response));
                        
                        sendto(ctx->sock_fd, &tx_frame, 14 + sizeof(struct file_meta) + sizeof(struct handshake_response), 
                               0, (struct sockaddr *)&remote_sll_arr[i], sll_len);
                        
                        ctx->processed_bytes = 0; 
                        ctx->state = STATE_RECEIVER_RECEIVING;
                        snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Receiving data...");
                    }
                    
                    // --- DATA FRAGMENT RECEIVED ---
                    else if (ctx->state == STATE_RECEIVER_RECEIVING && rx_frame->meta.opcode == OP_DATA) {
                        uint32_t seq = ntohl(rx_frame->meta.seq_num);
                        uint16_t payload_size = ntohs(rx_frame->meta.data_size);
                        
                        // If it's a valid fragment we haven't received yet
                        if (seq <= ctx->total_fragments && ctx->bitmap[seq] == 0) {
                            off_t offset = (off_t)(seq - 1) * ctx->neg_payload_size;
                            
                            // ZERO-COPY: Copy directly from the network socket into RAM-mapped file memory.
                            // The kernel will quietly write it to disk in the background.
                            if (ctx->file_map != NULL && ((uint64_t)offset + payload_size) <= ctx->total_bytes) {
                                memcpy(ctx->file_map + offset, rx_frame->payload, payload_size);
                            }
                            
                            ctx->bitmap[seq] = 1; 
                            ctx->processed_bytes += payload_size;
                            
                            // Check if the entire file has been successfully reconstructed
                            if (ctx->processed_bytes >= ctx->total_bytes) {
                                struct custom_frame tx_done;
                                memset(&tx_done, 0, sizeof(tx_done));
                                memcpy(tx_done.dest_mac, ctx->target_mac, 6);
                                memcpy(tx_done.src_mac, ctx->my_mac, 6);
                                tx_done.ether_type = htons(CUSTOM_ETHERTYPE);
                                tx_done.meta.opcode = OP_DONE;
                                
                                sendto(ctx->sock_fd, &tx_done, 14 + sizeof(struct file_meta), 
                                       0, (struct sockaddr *)&remote_sll_arr[i], sll_len);

                                // Unmap memory safely
                                munmap(ctx->file_map, ctx->total_bytes); 
                                ctx->file_map = NULL;
                                close(ctx->file_fd); 
                                ctx->file_fd = -1;
                                
                                if (ctx->is_dir_transfer) {
                                    ctx->state = STATE_RECEIVER_EXTRACTING;
                                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Reconstructing folder (safe mode)...");
                                } else {
                                    ctx->state = STATE_DONE;
                                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "File '%s' received! Press [ENTER] to continue.", ctx->original_filename);
                                }
                                break; 
                            }
                        }
                    }
                }
            } 
        } 

        // ---------------------------------------------------------
        // MISSING FRAGMENTS DETECTION (NACK Generation)
        // ---------------------------------------------------------
        // Because UDP/Raw frames get dropped easily, we must actively ask 
        // the sender to re-transmit the packets that didn't arrive.
        if (ctx->state == STATE_RECEIVER_RECEIVING) {
            static int nack_timer = 0;
            // Triggers every ~15 ticks to prevent flooding the network with NACKs
            if (nack_timer++ >= 15) { 
                nack_timer = 0;
                struct custom_frame nack_frame;
                memset(&nack_frame, 0, sizeof(nack_frame));
                memcpy(nack_frame.dest_mac, ctx->target_mac, 6);
                memcpy(nack_frame.src_mac, ctx->my_mac, 6);
                nack_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                nack_frame.meta.opcode = OP_NACK;
                
                struct nack_payload *np = (struct nack_payload *)nack_frame.payload;
                np->count = 0; 
                int total_requested = 0;
                
                // Scan the bitmap to find missing IDs
                for (uint32_t i = 1; i <= ctx->total_fragments; i++) {
                    if (ctx->bitmap[i] == 0) { 
                        np->sequences[np->count++] = htonl(i); 
                        total_requested++;
                        
                        // Send the NACK payload when full
                        if (np->count == 349) {
                            sendto(ctx->sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 
                                   0, (struct sockaddr *)&ctx->sll, sizeof(ctx->sll));
                            np->count = 0; 
                            usleep(50); // Tiny pause
                        }
                        if (total_requested >= 5000) break; // Request a max of 5000 fragments per cycle
                    }
                }
                
                // Send remaining requested fragments
                if (np->count > 0) {
                    sendto(ctx->sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 
                           0, (struct sockaddr *)&ctx->sll, sizeof(ctx->sll));
                }
                
                if (total_requested > 0) {
                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Recovering %d fragments...", total_requested);
                }
            }
        }
    }

    // ---------------------------------------------------------
    // STATE: EXTRACTING (For Directory Transfers)
    // ---------------------------------------------------------
    if (ctx->state == STATE_RECEIVER_EXTRACTING) {
        static int skipped_frames_recv = 0;
        if (skipped_frames_recv++ > 2) {
            skipped_frames_recv = 0;
            char recv_dir[512];
            snprintf(recv_dir, sizeof(recv_dir), "recv_%s", ctx->original_filename);
            mkdir(recv_dir, 0755); 
            
            // Secure extraction bypassing shell
            char *const tar_args[] = {"tar", "-xf", ctx->target_path, "-C", recv_dir, "--strip-components=1", NULL};
            if (execute_tar_safe(tar_args) == 0) {
                unlink(ctx->target_path); // Remove the temp archive
                snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Folder extracted! (%s/) Press [ENTER].", recv_dir);
            } else {
                snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Error extracting archive. Press [ENTER].");
            }
            ctx->state = STATE_DONE;
        }
    }
}
