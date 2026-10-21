/*
 * File: sender_engine.c
 * Description: Implements the Data Link layer sending logic. It handles
 * file archiving, handshake (PING/PONG), batch transmission of jumbo frames,
 * and reliable retransmission based on receiver NACKs.
 */

#include "sender_engine.h"
#include "system_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <libgen.h>

// Static buffers for high-performance batch transmission (sendmmsg)
// Kept static to avoid bloating the stack or the AppContext.
static struct mmsghdr tx_msgs[BATCH_SIZE];
static struct iovec tx_iov[BATCH_SIZE];
static struct custom_frame tx_frames[BATCH_SIZE];

void sender_engine_init(void) {
    memset(tx_msgs, 0, sizeof(tx_msgs));
    memset(tx_iov, 0, sizeof(tx_iov));
    memset(tx_frames, 0, sizeof(tx_frames));
}

void sender_engine_tick(AppContext *ctx) {
    // ---------------------------------------------------------
    // STATE: SENDER ARCHIVING (For Directory Transfers)
    // ---------------------------------------------------------
    if (ctx->state == STATE_SENDER_ARCHIVING) {
        static int skipped_frames = 0;
        // Skip a few frames to let the UI render the "Compressing..." message
        if (skipped_frames++ > 2) { 
            skipped_frames = 0;
            char *p1 = strdup(ctx->target_path);
            char *p2 = strdup(ctx->target_path);
            char *d_name = dirname(p1);
            char *b_name = basename(p2);
            
            snprintf(ctx->temp_tar_path, sizeof(ctx->temp_tar_path), "%s_transfer.tar", b_name);
            
            // Secure execution bypassing shell to prevent Shell Injection
            char *const tar_args[] = {"tar", "-cf", ctx->temp_tar_path, "-C", d_name, b_name, NULL};
            if (execute_tar_safe(tar_args) != 0) {
                ctx->state = STATE_ERROR;
                snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Error: failed to create tar archive.");
            } else {
                ctx->file_fd = open(ctx->temp_tar_path, O_RDONLY);
                if (ctx->file_fd < 0) {
                    ctx->state = STATE_ERROR;
                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Error: Cannot read tar archive.");
                } else {
                    ctx->total_bytes = lseek(ctx->file_fd, 0, SEEK_END); 
                    lseek(ctx->file_fd, 0, SEEK_SET);
                    ctx->state = STATE_SENDER_SENDING_PING;
                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Archive ready. Searching for receiver...");
                }
            }
            free(p1); free(p2);
        }
    }

    // ---------------------------------------------------------
    // STATE: SENDING PING (Handshake Initiation)
    // ---------------------------------------------------------
    else if (ctx->state == STATE_SENDER_SENDING_PING) {
        struct custom_frame ping;
        memset(&ping, 0, sizeof(ping));
        memset(ping.dest_mac, 0xFF, 6); // Broadcast MAC to find the receiver
        memcpy(ping.src_mac, ctx->my_mac, 6);
        ping.ether_type = htons(CUSTOM_ETHERTYPE);
        ping.meta.opcode = OP_PING;
        
        struct handshake_info hi;
        hi.total_bytes = ctx->total_bytes;
        hi.sender_mtu = htons((uint16_t)ctx->local_mtu);
        hi.is_dir = ctx->is_dir_transfer;
        snprintf(hi.filename, sizeof(hi.filename), "%s", ctx->original_filename); 
        
        memcpy(ping.payload, &hi, sizeof(struct handshake_info));
        sendto(ctx->sock_fd, &ping, 14 + sizeof(struct file_meta) + sizeof(struct handshake_info), 
               0, (struct sockaddr *)&ctx->sll, sizeof(ctx->sll));
        
        ctx->state = STATE_SENDER_WAITING_PONG;
    }
    
    // ---------------------------------------------------------
    // STATE: WAITING PONG (Handshake Response)
    // ---------------------------------------------------------
    else if (ctx->state == STATE_SENDER_WAITING_PONG) {
        unsigned char buffer[sizeof(struct custom_frame)];
        ssize_t rx_size = recvfrom(ctx->sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);
        if (rx_size > 0) {
            struct custom_frame *rx_frame = (struct custom_frame *)buffer;
            
            // Verify correct ethertype and opcode
            if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE && rx_frame->meta.opcode == OP_PONG) {
                struct handshake_response *hr = (struct handshake_response *)rx_frame->payload;
                
                // Finalize network parameters based on receiver's capabilities
                ctx->negotiated_mtu = ntohs(hr->negotiated_mtu);
                ctx->total_fragments = ntohl(hr->total_fragments);
                
                ctx->neg_payload_size = ctx->negotiated_mtu - sizeof(struct file_meta);
                if (ctx->neg_payload_size > MAX_JUMBO_PAYLOAD) {
                    ctx->neg_payload_size = MAX_JUMBO_PAYLOAD;
                }

                // Lock onto receiver's MAC address to switch from Broadcast to Unicast
                memcpy(ctx->target_mac, rx_frame->src_mac, 6);
                ctx->sequence = 1; 
                ctx->processed_bytes = 0;
                
                ctx->state = STATE_SENDER_TRANSFERRING;
                snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Transfer in progress...");
            }
        }
    }
    
    // ---------------------------------------------------------
    // STATE: TRANSFERRING (High-Speed Data Loop)
    // ---------------------------------------------------------
    else if (ctx->state == STATE_SENDER_TRANSFERRING) {
        int sent_this_cycle = 0;
        uint8_t eof_reached = 0;

        // Inner loop: Send up to ~10,000 packets per tick to saturate the link without freezing UI
        // Very large limit (50000 batches = theoretical tens of Gigabytes/s)
        while (sent_this_cycle < 50000 && !eof_reached) {
            int batch_count = 0;
            
            // Reinserted the missing file reading logic
            for (int i = 0; i < BATCH_SIZE; i++) {
                memset(&tx_frames[i], 0, sizeof(struct custom_frame));
                memcpy(tx_frames[i].dest_mac, ctx->target_mac, 6);
                memcpy(tx_frames[i].src_mac, ctx->my_mac, 6);
                tx_frames[i].ether_type = htons(CUSTOM_ETHERTYPE);
                tx_frames[i].meta.opcode = OP_DATA;
                
                ssize_t bytes_read = read(ctx->file_fd, tx_frames[i].payload, ctx->neg_payload_size);
                if (bytes_read > 0) {
                    tx_frames[i].meta.seq_num = htonl(ctx->sequence++);
                    tx_frames[i].meta.data_size = htons((uint16_t)bytes_read);
                    tx_frames[i].meta.is_eof = (ctx->sequence > ctx->total_fragments) ? 1 : 0;
                    
                    tx_iov[i].iov_base = &tx_frames[i];
                    tx_iov[i].iov_len = 14 + sizeof(struct file_meta) + bytes_read;
                    
                    tx_msgs[i].msg_hdr.msg_iov = &tx_iov[i];
                    tx_msgs[i].msg_hdr.msg_iovlen = 1;
                    tx_msgs[i].msg_hdr.msg_name = &ctx->sll;
                    tx_msgs[i].msg_hdr.msg_namelen = sizeof(ctx->sll);
                    
                    ctx->processed_bytes += bytes_read; 
                    batch_count++;
                    
                    if (tx_frames[i].meta.is_eof) { 
                        eof_reached = 1; 
                        break; 
                    }
                } else break; // EOF reached
            }

            if (batch_count > 0) { 
                // Check how many packets the hardware ACTUALLY accepted
                int sent = sendmmsg(ctx->sock_fd, tx_msgs, batch_count, 0); 
                
                // If the hardware queue is full, sendmmsg returns -1 (ENOBUFS/EAGAIN)
                if (sent < 0) sent = 0; 

                // If we failed to send the entire batch, apply Backpressure
                if (sent < batch_count) {
                    off_t rewind_bytes = 0;
                    
                    // Calculate how many bytes we must "give back" to the file
                    for (int j = sent; j < batch_count; j++) {
                        rewind_bytes += ntohs(tx_frames[j].meta.data_size);
                        ctx->sequence--; // Rollback the incorrectly advanced sequence numbers
                    }
                    
                    ctx->processed_bytes -= rewind_bytes;
                    lseek(ctx->file_fd, -rewind_bytes, SEEK_CUR); // Rewind the file pointer
                    
                    eof_reached = 0; // If EOF was flagged in this dropped batch, clear it
                    
                    // Break the while loop for this tick. 
                    // This gives the kernel time to drain the hardware queue to the wire.
                    break; 
                }
                
                sent_this_cycle += sent; 
            } 
            else {
                break; 
            }
        }
        
        if (eof_reached) {
            ctx->state = STATE_SENDER_WAITING_NACK;
            snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Integrity check in progress...");
        }
    }
    
    // ---------------------------------------------------------
    // STATE: WAITING NACK (Reliability / Retransmission)
    // ---------------------------------------------------------
    else if (ctx->state == STATE_SENDER_WAITING_NACK) {
        while (1) {
            unsigned char buffer[65536];
            ssize_t rx_size = recvfrom(ctx->sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);
            if (rx_size < 0) break; // No packets pending
            
            struct custom_frame *rx_frame = (struct custom_frame *)buffer;
            if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                
                if (rx_frame->meta.opcode == OP_NACK) {
                    struct nack_payload *np = (struct nack_payload *)rx_frame->payload;
                    // Resend only the missing fragments
                    for(int i = 0; i < np->count; i++) {
                        uint32_t missing_seq = ntohl(np->sequences[i]);
                        struct custom_frame data_frame;
                        
                        memset(&data_frame, 0, sizeof(data_frame));
                        memcpy(data_frame.dest_mac, ctx->target_mac, 6);
                        memcpy(data_frame.src_mac, ctx->my_mac, 6);
                        data_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                        data_frame.meta.opcode = OP_DATA;
                        data_frame.meta.seq_num = htonl(missing_seq);
                        
                        // Use pread to fetch the exact missing chunk without moving the global file pointer
                        off_t offset = (off_t)(missing_seq - 1) * ctx->neg_payload_size;
                        ssize_t bytes_read = pread(ctx->file_fd, data_frame.payload, ctx->neg_payload_size, offset);
                        
                        if (bytes_read > 0) {
                            data_frame.meta.data_size = htons((uint16_t)bytes_read);
                            sendto(ctx->sock_fd, &data_frame, 14 + sizeof(struct file_meta) + bytes_read, 
                                   0, (struct sockaddr *)&ctx->sll, sizeof(ctx->sll));
                        }
                    }
                }
                else if (rx_frame->meta.opcode == OP_DONE) {
                    ctx->state = STATE_DONE;
                    snprintf(ctx->status_msg, sizeof(ctx->status_msg), "Transfer complete! Press [ENTER] to continue.");
                    break; 
                }
            }
        }
    }
}
