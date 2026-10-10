/*
- File: tui_raw_transfer.c
- Descrizione: Applicazione TUI in C per il trasferimento raw di Livello 2 (Data Link).
-              MIGLIORATA: Include un File Browser TUI integrato, esecuzione
-              sicura di comandi esterni (fork/execvp per prevenire Shell Injection)
-              e supporto per trasferimenti continui multipli.
 */

#define _GNU_SOURCE

// ==============================================================================
// LIBRERIE
// ==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>              
#include <sys/stat.h>           
#include <sys/ioctl.h>          
#include <sys/socket.h>         
#include <net/if.h>             
#include <arpa/inet.h>          
#include <linux/if_packet.h>    
#include <netinet/if_ether.h>   
#include <ifaddrs.h>            
#include <sys/mman.h>           
#include <sys/time.h>           
#include <libgen.h>             
#include <dirent.h>             // Per il File Browser
#include <sys/wait.h>           // Per fork() e waitpid() (Sicurezza)
#include <ncurses.h>            
#include <errno.h>
#include <signal.h>

#define CUSTOM_ETHERTYPE 0x88B5     

#define OP_PING 0   
#define OP_PONG 1   
#define OP_DATA 2   
#define OP_NACK 3   
#define OP_DONE 4   

#define BATCH_SIZE 256              
#define MAX_JUMBO_PAYLOAD 8950      
#define MAX_DIR_ENTRIES 1024

// ==============================================================================
// STRUTTURE DATI
// ==============================================================================
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

typedef enum {
    STATE_SELECT_INTERFACE,
    STATE_IDLE,
    STATE_BROWSE_FILES,        // Nuovo stato per il File Browser
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

// Struttura per il File Browser
typedef struct {
    char name[256];
    int is_dir;
} FileEntry;

long long current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

// Esecuzione sicura di binari bypassando la shell (Antidoto alla Shell Injection)
int execute_tar_safe(char *const args[]) {
    pid_t pid = fork();
    if (pid == 0) {
        // Processo figlio: esegue il comando scartando l'interprete dei comandi
        execvp("tar", args);
        exit(127); // Raggiunto solo in caso di fallimento di execvp
    } else if (pid > 0) {
        // Processo padre: attende la fine
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    return -1; // Fallimento di fork()
}

// Funzione di utility per ordinare le directory (cartelle in cima)
int compare_entries(const void *a, const void *b) {
    FileEntry *e1 = (FileEntry *)a;
    FileEntry *e2 = (FileEntry *)b;
    if (strcmp(e1->name, "..") == 0) return -1;
    if (strcmp(e2->name, "..") == 0) return 1;
    if (e1->is_dir && !e2->is_dir) return -1;
    if (!e1->is_dir && e2->is_dir) return 1;
    return strcasecmp(e1->name, e2->name);
}

// Carica il contenuto della directory
void load_directory(const char* path, FileEntry* entries, int* count) {
    *count = 0;
    struct dirent **namelist;
    int n = scandir(path, &namelist, NULL, alphasort);
    if (n < 0) return;

    for (int i = 0; i < n; i++) {
        if (strcmp(namelist[i]->d_name, ".") == 0) {
            free(namelist[i]); continue;
        }
        strncpy(entries[*count].name, namelist[i]->d_name, 255);
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, namelist[i]->d_name);
        struct stat st;
        if (stat(full_path, &st) == 0) {
            entries[*count].is_dir = S_ISDIR(st.st_mode);
        } else {
            entries[*count].is_dir = (namelist[i]->d_type == DT_DIR);
        }
        
        free(namelist[i]);
        (*count)++;
        if (*count >= MAX_DIR_ENTRIES) break;
    }
    free(namelist);
    qsort(entries, *count, sizeof(FileEntry), compare_entries);
}

int setup_network(const char *ifname, int *sock_fd, unsigned char *my_mac, struct sockaddr_ll *sll, int *local_mtu, int *original_mtu) {
    *sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*sock_fd < 0) return -1;

    int rcvbuf = 32 * 1024 * 1024; 
    setsockopt(*sock_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    if (ioctl(*sock_fd, SIOCGIFINDEX, &ifr) < 0) return -2;
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(*sock_fd, SIOCGIFHWADDR, &ifr) < 0) return -3;
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(*sock_fd, SIOCGIFMTU, &ifr) == 0) *original_mtu = ifr.ifr_mtu;
    else *original_mtu = 1500; 

    ifr.ifr_mtu = 9000;
    if (ioctl(*sock_fd, SIOCSIFMTU, &ifr) == 0) *local_mtu = 9000;
    else *local_mtu = *original_mtu; 

    memset(sll, 0, sizeof(*sll));
    sll->sll_family = AF_PACKET;
    sll->sll_protocol = htons(ETH_P_ALL);
    sll->sll_ifindex = ifindex;
    if (bind(*sock_fd, (struct sockaddr *)sll, sizeof(*sll)) < 0) return -4;
    
    return 0;
}

// Flag volatile sicuro per i segnali asincroni
volatile sig_atomic_t g_shutdown_requested = 0;

void handle_signal(int sig) {
    g_shutdown_requested = 1;
}

// ==============================================================================
// MAIN LOOP
// ==============================================================================
int main(int argc, char *argv[]) {
    
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE); 
    curs_set(0);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    char interface_list[10][IFNAMSIZ];
    int interface_count = 0;
    int current_selection = 0;
    char active_interface[IFNAMSIZ] = "";

    // Variabili per il File Browser
    char current_dir[1024];
    getcwd(current_dir, sizeof(current_dir));
    FileEntry dir_entries[MAX_DIR_ENTRIES];
    int entry_count = 0;
    int browser_sel = 0;
    int scroll_offset = 0;

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family == AF_PACKET && interface_count < 10) {
                char sysfs_path[256];
                snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/wireless", ifa->ifa_name);
                if (access(sysfs_path, F_OK) == 0) continue; 
                strncpy(interface_list[interface_count], ifa->ifa_name, IFNAMSIZ - 1);
                interface_count++;
            }
        }
        freeifaddrs(ifaddr);
    }

    int sock_fd = -1;
    unsigned char my_mac[6], target_mac[6];
    struct sockaddr_ll sll;
    
    int file_fd = -1;                       
    uint64_t total_bytes = 1;               
    uint64_t processed_bytes = 0;           
    uint32_t total_fragments = 0;           
    uint32_t sequence = 1;                  
    uint8_t *bitmap = NULL;                
    uint8_t *file_map = NULL;             
    
    char target_path[1024] = "";
    char temp_tar_path[1024] = "";
    char original_filename[256] = ""; 
    int is_dir_transfer = 0;

    int local_mtu = 1500, original_mtu = 1500, negotiated_mtu = 1500, neg_payload_size = 1400;
    
    static struct mmsghdr rx_msgs[BATCH_SIZE];
    static struct iovec rx_iov[BATCH_SIZE];
    static struct custom_frame rx_frames[BATCH_SIZE];
    static struct sockaddr_ll remote_sll_arr[BATCH_SIZE];

    static struct mmsghdr tx_msgs[BATCH_SIZE];
    static struct iovec tx_iov[BATCH_SIZE];
    static struct custom_frame tx_frames[BATCH_SIZE];
    
    for (int i = 0; i < BATCH_SIZE; i++) {
        rx_iov[i].iov_base = &rx_frames[i];
        rx_iov[i].iov_len = sizeof(struct custom_frame);
        rx_msgs[i].msg_hdr.msg_iov = &rx_iov[i];
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
        rx_msgs[i].msg_hdr.msg_name = &remote_sll_arr[i];
        rx_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
    }

    AppState state = STATE_SELECT_INTERFACE;
    char status_msg[128] = "Utilizza le frecce direzionali e INVIO.";

    int running = 1;
    long long last_draw_time = 0; 

    while (running) {

        if (g_shutdown_requested) {
            running = 0;
            break;
        }

        int ch = getch();
        
        // GESTIONE DEI RESET GLOBALI DOPO IL TRASFERIMENTO
        if ((state == STATE_DONE || state == STATE_ERROR) && ch != ERR) {
            if (ch == 'q' || ch == 'Q') {
                running = 0;
            } else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 'r' || ch == 'i') {
                // Reset Variabili Trasferimento
                if (bitmap != NULL) { free(bitmap); bitmap = NULL; }
                if (file_fd >= 0) { close(file_fd); file_fd = -1; }
                if (file_map != NULL && file_map != MAP_FAILED) { munmap(file_map, total_bytes); file_map = NULL; }
                if (strlen(temp_tar_path) > 0) { unlink(temp_tar_path); temp_tar_path[0] = '\0'; }
                
                target_path[0] = '\0';
                processed_bytes = 0; sequence = 1; total_bytes = 1; total_fragments = 0;
                
                state = STATE_IDLE;
                snprintf(status_msg, sizeof(status_msg), "Pronto. [R] Ricevi | [I] Invia | [Q] Esci");
            }
        }

        if (ch != ERR && state != STATE_DONE && state != STATE_ERROR) {
            if (ch == 'q' || ch == 'Q') {
                running = 0; 
            } 
            else if (state == STATE_SELECT_INTERFACE) {
                if ((ch == KEY_UP || ch == 'k' || ch == 'K') && current_selection > 0) current_selection--;
                else if ((ch == KEY_DOWN || ch == 'j' || ch == 'J') && current_selection < interface_count - 1) current_selection++;
                else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) { 
                    strncpy(active_interface, interface_list[current_selection], IFNAMSIZ);
                    if (setup_network(active_interface, &sock_fd, my_mac, &sll, &local_mtu, &original_mtu) == 0) {
                        state = STATE_IDLE;
                        snprintf(status_msg, sizeof(status_msg), "Pronto. [R] Ricevi | [I] Invia | [Q] Esci");
                    } else {
                        state = STATE_ERROR;
                        snprintf(status_msg, sizeof(status_msg), "Errore di inizializzazione rete.");
                    }
                }
            }
            else if ((ch == 'r' || ch == 'R') && state == STATE_IDLE) {
                state = STATE_RECEIVER_WAITING_PING;
                snprintf(status_msg, sizeof(status_msg), "In ascolto su %s...", active_interface);
            } 
            else if ((ch == 'i' || ch == 'I') && state == STATE_IDLE) {
                state = STATE_BROWSE_FILES;
                load_directory(current_dir, dir_entries, &entry_count);
                browser_sel = 0;
                scroll_offset = 0;
                snprintf(status_msg, sizeof(status_msg), "Seleziona file o cartella da inviare.");
            }
            else if (state == STATE_BROWSE_FILES) {
                if (ch == KEY_UP && browser_sel > 0) browser_sel--;
                else if (ch == KEY_DOWN && browser_sel < entry_count - 1) browser_sel++;
                else if (ch == 27 || ch == 'b' || ch == 'B') { // ESC or 'b' per tornare indietro all'IDLE
                    state = STATE_IDLE;
                    snprintf(status_msg, sizeof(status_msg), "Pronto. [R] Ricevi | [I] Invia | [Q] Esci");
                }
                else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 's' || ch == 'S') {
                    FileEntry *sel_entry = &dir_entries[browser_sel];
                    
                    // Se premiamo INVIO su una Directory entra in essa, a meno che non si prema 's'
                    if (sel_entry->is_dir && ch != 's' && ch != 'S') {
                        char new_path[1024];
                        snprintf(new_path, sizeof(new_path), "%s/%s", current_dir, sel_entry->name);
                        char resolved_path[1024];
                        realpath(new_path, resolved_path); // Risolve il ".." automaticamente
                        strncpy(current_dir, resolved_path, sizeof(current_dir));
                        load_directory(current_dir, dir_entries, &entry_count);
                        browser_sel = 0; scroll_offset = 0;
                    } 
                    // Se premiamo 's' (su qualsiasi cosa) o INVIO su un file -> AVVIA TRASFERIMENTO
                    else if (strcmp(sel_entry->name, "..") != 0) {
                        snprintf(target_path, sizeof(target_path), "%s/%s", current_dir, sel_entry->name);
                        is_dir_transfer = sel_entry->is_dir;
                        
                        char *path_copy = strdup(target_path);
                        strncpy(original_filename, basename(path_copy), sizeof(original_filename) - 1);
                        free(path_copy);

                        if (is_dir_transfer) {
                            state = STATE_SENDER_ARCHIVING;
                            snprintf(status_msg, sizeof(status_msg), "Compressione cartella in corso (sicura)...");
                        } else {
                            file_fd = open(target_path, O_RDONLY);
                            if (file_fd < 0) {
                                state = STATE_ERROR;
                                snprintf(status_msg, sizeof(status_msg), "Errore: Impossibile aprire '%s'.", target_path);
                            } else {
                                total_bytes = lseek(file_fd, 0, SEEK_END); 
                                lseek(file_fd, 0, SEEK_SET);               
                                state = STATE_SENDER_SENDING_PING;
                                snprintf(status_msg, sizeof(status_msg), "Ricerca ricevitore...");
                            }
                        }
                    }
                }

                // Scrolling logica
                if (browser_sel < scroll_offset) scroll_offset = browser_sel;
                if (browser_sel >= scroll_offset + 10) scroll_offset = browser_sel - 9;
            }
        }

        // ==============================================================================
        // LATO MITTENTE (Sender)
        // ==============================================================================

        if (state == STATE_SENDER_ARCHIVING) {
            static int skipped_frames = 0;
            if (skipped_frames++ > 2) { // Tempo all'UI di renderizzare il testo
                skipped_frames = 0;
                char *p1 = strdup(target_path);
                char *p2 = strdup(target_path);
                char *d_name = dirname(p1);
                char *b_name = basename(p2);
                
                snprintf(temp_tar_path, sizeof(temp_tar_path), "%s_transfer.tar", b_name);
                
                // UTILIZZO FORK/EXECVP INVECE DI SYSTEM() PER EVITARE SHELL INJECTION
                char *const tar_args[] = {"tar", "-cf", temp_tar_path, "-C", d_name, b_name, NULL};
                
                if (execute_tar_safe(tar_args) != 0) {
                    state = STATE_ERROR;
                    snprintf(status_msg, sizeof(status_msg), "Errore: fallita la creazione dell'archivio tar.");
                } else {
                    file_fd = open(temp_tar_path, O_RDONLY);
                    if (file_fd < 0) {
                        state = STATE_ERROR;
                        snprintf(status_msg, sizeof(status_msg), "Errore: Impossibile leggere archivio tar.");
                    } else {
                        total_bytes = lseek(file_fd, 0, SEEK_END); 
                        lseek(file_fd, 0, SEEK_SET);
                        state = STATE_SENDER_SENDING_PING;
                        snprintf(status_msg, sizeof(status_msg), "Archivio pronto. Ricerca ricevitore...");
                    }
                }
                free(p1); free(p2);
            }
        }

        else if (state == STATE_SENDER_SENDING_PING) {
            struct custom_frame ping;
            memset(&ping, 0, sizeof(ping));
            memset(ping.dest_mac, 0xFF, 6); 
            memcpy(ping.src_mac, my_mac, 6);
            ping.ether_type = htons(CUSTOM_ETHERTYPE);
            ping.meta.opcode = OP_PING;
            
            struct handshake_info hi;
            hi.total_bytes = total_bytes;
            hi.sender_mtu = htons((uint16_t)local_mtu);
            hi.is_dir = is_dir_transfer;
            strncpy(hi.filename, original_filename, sizeof(hi.filename) - 1); 
            
            memcpy(ping.payload, &hi, sizeof(struct handshake_info));
            sendto(sock_fd, &ping, 14 + sizeof(struct file_meta) + sizeof(struct handshake_info), 0, (struct sockaddr *)&sll, sizeof(sll));
            state = STATE_SENDER_WAITING_PONG;
        }
        
        else if (state == STATE_SENDER_WAITING_PONG) {
            unsigned char buffer[2048];
            ssize_t rx_size = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);
            if (rx_size > 0) {
                struct custom_frame *rx_frame = (struct custom_frame *)buffer;
                if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE && rx_frame->meta.opcode == OP_PONG) {
                    struct handshake_response *hr = (struct handshake_response *)rx_frame->payload;
                    negotiated_mtu = ntohs(hr->negotiated_mtu);
                    total_fragments = ntohl(hr->total_fragments);
                    
                    neg_payload_size = negotiated_mtu - sizeof(struct file_meta);
                    if (neg_payload_size > MAX_JUMBO_PAYLOAD) neg_payload_size = MAX_JUMBO_PAYLOAD;

                    memcpy(target_mac, rx_frame->src_mac, 6);
                    sequence = 1; processed_bytes = 0;
                    state = STATE_SENDER_TRANSFERRING;
                    snprintf(status_msg, sizeof(status_msg), "Trasferimento in corso...");
                }
            }
        }
        
        else if (state == STATE_SENDER_TRANSFERRING) {
            int sent_this_cycle = 0;
            uint8_t eof_reached = 0;

            while (sent_this_cycle < 10000 && !eof_reached) {
                int batch_count = 0;
                memset(tx_msgs, 0, sizeof(tx_msgs));

                for (int i = 0; i < BATCH_SIZE; i++) {
                    memset(&tx_frames[i], 0, sizeof(struct custom_frame));
                    memcpy(tx_frames[i].dest_mac, target_mac, 6);
                    memcpy(tx_frames[i].src_mac, my_mac, 6);
                    tx_frames[i].ether_type = htons(CUSTOM_ETHERTYPE);
                    tx_frames[i].meta.opcode = OP_DATA;
                    
                    ssize_t bytes_read = read(file_fd, tx_frames[i].payload, neg_payload_size);
                    if (bytes_read > 0) {
                        tx_frames[i].meta.seq_num = htonl(sequence++);
                        tx_frames[i].meta.data_size = htons((uint16_t)bytes_read);
                        tx_frames[i].meta.is_eof = (sequence > total_fragments) ? 1 : 0;
                        tx_iov[i].iov_base = &tx_frames[i];
                        tx_iov[i].iov_len = 14 + sizeof(struct file_meta) + bytes_read;
                        tx_msgs[i].msg_hdr.msg_iov = &tx_iov[i];
                        tx_msgs[i].msg_hdr.msg_iovlen = 1;
                        tx_msgs[i].msg_hdr.msg_name = &sll;
                        tx_msgs[i].msg_hdr.msg_namelen = sizeof(sll);
                        processed_bytes += bytes_read; batch_count++;
                        if (tx_frames[i].meta.is_eof) { eof_reached = 1; break; }
                    } else break;
                }
                if (batch_count > 0) { sendmmsg(sock_fd, tx_msgs, batch_count, 0); sent_this_cycle += batch_count; } 
                else break; 
            }
            if (eof_reached) {
                state = STATE_SENDER_WAITING_NACK;
                snprintf(status_msg, sizeof(status_msg), "Verifica integrità in corso...");
            }
        }
        
        else if (state == STATE_SENDER_WAITING_NACK) {
            while (1) {
                unsigned char buffer[65536];
                ssize_t rx_size = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);
                if (rx_size < 0) break; 
                
                struct custom_frame *rx_frame = (struct custom_frame *)buffer;
                if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                    if (rx_frame->meta.opcode == OP_NACK) {
                        struct nack_payload *np = (struct nack_payload *)rx_frame->payload;
                        for(int i = 0; i < np->count; i++) {
                            uint32_t missing_seq = ntohl(np->sequences[i]);
                            struct custom_frame data_frame;
                            memset(&data_frame, 0, sizeof(data_frame));
                            memcpy(data_frame.dest_mac, target_mac, 6);
                            memcpy(data_frame.src_mac, my_mac, 6);
                            data_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                            data_frame.meta.opcode = OP_DATA;
                            data_frame.meta.seq_num = htonl(missing_seq);
                            
                            off_t offset = (off_t)(missing_seq - 1) * neg_payload_size;
                            ssize_t bytes_read = pread(file_fd, data_frame.payload, neg_payload_size, offset);
                            
                            if (bytes_read > 0) {
                                data_frame.meta.data_size = htons((uint16_t)bytes_read);
                                sendto(sock_fd, &data_frame, 14 + sizeof(struct file_meta) + bytes_read, 0, (struct sockaddr *)&sll, sizeof(sll));
                            }
                        }
                    }
                    else if (rx_frame->meta.opcode == OP_DONE) {
                        state = STATE_DONE;
                        snprintf(status_msg, sizeof(status_msg), "Trasferimento completato! Premi [INVIO] per continuare.");
                        break; 
                    }
                }
            }
        }

        // ==============================================================================
        // LATO RICEVITORE (Receiver)
        // ==============================================================================
        if (state == STATE_RECEIVER_WAITING_PING || state == STATE_RECEIVER_RECEIVING) {
            while (1) {
                int vlen = recvmmsg(sock_fd, rx_msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
                if (vlen < 0) break; 
                
                for (int i = 0; i < vlen; i++) {
                    struct custom_frame *rx_frame = &rx_frames[i];
                    socklen_t sll_len = rx_msgs[i].msg_hdr.msg_namelen;
                    
                    if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                        if (state == STATE_RECEIVER_WAITING_PING && rx_frame->meta.opcode == OP_PING) {
                            memcpy(target_mac, rx_frame->src_mac, 6);
                            
                            struct handshake_info *hi = (struct handshake_info *)rx_frame->payload;
                            total_bytes = hi->total_bytes;
                            uint16_t sender_mtu = ntohs(hi->sender_mtu);
                            is_dir_transfer = hi->is_dir;
                            strncpy(original_filename, hi->filename, sizeof(original_filename) - 1);
                            
                            if (is_dir_transfer) snprintf(target_path, sizeof(target_path), "recv_%s.tar", original_filename);
                            else snprintf(target_path, sizeof(target_path), "recv_%s", original_filename);
                            
                            negotiated_mtu = (sender_mtu < local_mtu) ? sender_mtu : local_mtu;
                            neg_payload_size = negotiated_mtu - sizeof(struct file_meta);
                            if (neg_payload_size > MAX_JUMBO_PAYLOAD) neg_payload_size = MAX_JUMBO_PAYLOAD;
                            
                            total_fragments = (total_bytes + neg_payload_size - 1) / neg_payload_size;
                            bitmap = calloc(total_fragments + 1, sizeof(uint8_t));
                            
                            file_fd = open(target_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
                            ftruncate(file_fd, total_bytes); 
                            file_map = mmap(NULL, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, file_fd, 0);
                            
                            struct custom_frame tx_frame;
                            memset(&tx_frame, 0, sizeof(tx_frame));
                            memcpy(tx_frame.dest_mac, target_mac, 6);
                            memcpy(tx_frame.src_mac, my_mac, 6);
                            tx_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                            tx_frame.meta.opcode = OP_PONG;
                            
                            struct handshake_response hr;
                            hr.negotiated_mtu = htons(negotiated_mtu);
                            hr.total_fragments = htonl(total_fragments);
                            memcpy(tx_frame.payload, &hr, sizeof(struct handshake_response));
                            
                            sendto(sock_fd, &tx_frame, 14 + sizeof(struct file_meta) + sizeof(struct handshake_response), 0, (struct sockaddr *)&remote_sll_arr[i], sll_len);
                            
                            processed_bytes = 0; 
                            state = STATE_RECEIVER_RECEIVING;
                            snprintf(status_msg, sizeof(status_msg), "Ricezione dati in corso...");
                        }
                        
                        else if (state == STATE_RECEIVER_RECEIVING && rx_frame->meta.opcode == OP_DATA) {
                            uint32_t seq = ntohl(rx_frame->meta.seq_num);
                            uint16_t payload_size = ntohs(rx_frame->meta.data_size);
                            
                            if (seq <= total_fragments && bitmap[seq] == 0) {
                                off_t offset = (off_t)(seq - 1) * neg_payload_size;
                                if (file_map != NULL && (offset + payload_size) <= total_bytes) {
                                    memcpy(file_map + offset, rx_frame->payload, payload_size);
                                }
                                bitmap[seq] = 1; processed_bytes += payload_size;
                                
                                if (processed_bytes >= total_bytes) {
                                    struct custom_frame tx_done;
                                    memset(&tx_done, 0, sizeof(tx_done));
                                    memcpy(tx_done.dest_mac, target_mac, 6);
                                    memcpy(tx_done.src_mac, my_mac, 6);
                                    tx_done.ether_type = htons(CUSTOM_ETHERTYPE);
                                    tx_done.meta.opcode = OP_DONE;
                                    sendto(sock_fd, &tx_done, 14 + sizeof(struct file_meta), 0, (struct sockaddr *)&remote_sll_arr[i], sll_len);

                                    munmap(file_map, total_bytes); file_map = NULL;
                                    close(file_fd); file_fd = -1;
                                    
                                    if (is_dir_transfer) {
                                        state = STATE_RECEIVER_EXTRACTING;
                                        snprintf(status_msg, sizeof(status_msg), "Ricostruzione cartella in corso (sicura)...");
                                    } else {
                                        state = STATE_DONE;
                                        snprintf(status_msg, sizeof(status_msg), "File '%s' ricevuto! Premi [INVIO] per continuare.", original_filename);
                                    }
                                    break; 
                                }
                            }
                        }
                    }
                } 
            } 

            if (state == STATE_RECEIVER_RECEIVING) {
                static int nack_timer = 0;
                if (nack_timer++ >= 15) { 
                    nack_timer = 0;
                    struct custom_frame nack_frame;
                    memset(&nack_frame, 0, sizeof(nack_frame));
                    memcpy(nack_frame.dest_mac, target_mac, 6);
                    memcpy(nack_frame.src_mac, my_mac, 6);
                    nack_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                    nack_frame.meta.opcode = OP_NACK;
                    
                    struct nack_payload *np = (struct nack_payload *)nack_frame.payload;
                    np->count = 0; int total_requested = 0;
                    for (uint32_t i = 1; i <= total_fragments; i++) {
                        if (bitmap[i] == 0) { 
                            np->sequences[np->count++] = htonl(i); total_requested++;
                            if (np->count == 349) {
                                sendto(sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 0, (struct sockaddr *)&sll, sizeof(sll));
                                np->count = 0; usleep(50); 
                            }
                            if (total_requested >= 5000) break; 
                        }
                    }
                    if (np->count > 0) sendto(sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 0, (struct sockaddr *)&sll, sizeof(sll));
                    if (total_requested > 0) snprintf(status_msg, sizeof(status_msg), "Recupero di %d frammenti...", total_requested);
                }
            }
        }

        if (state == STATE_RECEIVER_EXTRACTING) {
            static int skipped_frames_recv = 0;
            if (skipped_frames_recv++ > 2) {
                skipped_frames_recv = 0;
                char recv_dir[1024];
                snprintf(recv_dir, sizeof(recv_dir), "recv_%s", original_filename);
                mkdir(recv_dir, 0755); 
                
                // UTILIZZO FORK/EXECVP INVECE DI SYSTEM() PER L'ESTRAZIONE
                char *const tar_args[] = {"tar", "-xf", target_path, "-C", recv_dir, "--strip-components=1", NULL};
                
                if (execute_tar_safe(tar_args) == 0) {
                    unlink(target_path); // Rimuove l'archivio
                    snprintf(status_msg, sizeof(status_msg), "Cartella estratta! (%s/) Premi [INVIO].", recv_dir);
                } else {
                    snprintf(status_msg, sizeof(status_msg), "Errore di estrazione archivio. Premi [INVIO].");
                }
                state = STATE_DONE;
            }
        }

        // ==============================================================================
        // GESTIONE INTERFACCIA UTENTE (TUI NCURSES)
        // ==============================================================================
        long long now = current_time_ms();
        if (now - last_draw_time >= 16) { 
            erase(); 
            box(stdscr, 0, 0);

            attron(A_BOLD);
            mvprintw(1, 2, " RAW L2 TRANSFER ");
            attroff(A_BOLD);
            mvprintw(2, 2, "---------------------------------------------");

            if (state == STATE_SELECT_INTERFACE) {
                mvprintw(4, 4, "Seleziona scheda di rete:");
                for (int i = 0; i < interface_count; i++) {
                    if (i == current_selection) attron(A_REVERSE); 
                    mvprintw(6 + i, 6, " %s %s ", i == current_selection ? ">" : " ", interface_list[i]);
                    if (i == current_selection) attroff(A_REVERSE);
                }
            } 
            else if (state == STATE_BROWSE_FILES) {
                mvprintw(4, 4, "Dir: %s", current_dir);
                mvprintw(5, 4, "[INVIO] Entra/Invia File | [S] Invia Selezionato | [ESC] Indietro");
                for (int i = 0; i < 10 && (scroll_offset + i) < entry_count; i++) {
                    int idx = scroll_offset + i;
                    if (idx == browser_sel) attron(A_REVERSE);
                    mvprintw(7 + i, 6, " %s %s ", dir_entries[idx].is_dir ? "[DIR] " : "      ", dir_entries[idx].name);
                    if (idx == browser_sel) attroff(A_REVERSE);
                }
            }
            else {
                mvprintw(4, 4, "Interfaccia: %s | MTU Rete: %d", active_interface, negotiated_mtu);
                mvprintw(5, 4, "Stato: %s", status_msg);
                
                if (state != STATE_ERROR) {
                    mvprintw(7, 4, "Mio MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
                             my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
                }
                
                if (state == STATE_SENDER_TRANSFERRING || state == STATE_RECEIVER_RECEIVING || 
                    state == STATE_DONE || state == STATE_SENDER_WAITING_NACK || state == STATE_RECEIVER_EXTRACTING) {
                    mvprintw(8, 4, "MAC Target: %02x:%02x:%02x:%02x:%02x:%02x", 
                             target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
                
                    int bar_width = 40;
                    int filled = (total_bytes > 0) ? (processed_bytes * bar_width) / total_bytes : 0;
                    if (filled > bar_width) filled = bar_width;
                    
                    mvprintw(10, 4, "[");
                    for (int i = 0; i < bar_width; i++) addch(i < filled ? '#' : '-');
                    printw("] %d%% (%llu/%llu byte) %s", 
                           (total_bytes > 0) ? (int)((processed_bytes * 100) / total_bytes) : 0, 
                           (unsigned long long)processed_bytes, (unsigned long long)total_bytes, 
                           is_dir_transfer ? "[DIRECTORY]" : "[FILE]");
                }
            }
            refresh();
            last_draw_time = now; 
        }

        if (state != STATE_SENDER_TRANSFERRING && state != STATE_RECEIVER_RECEIVING && state != STATE_SENDER_WAITING_NACK) {
            usleep(16000); 
        }
    }

    // ==============================================================================
    // CLEANUP GLOBALE
    // ==============================================================================
    if (strlen(temp_tar_path) > 0) unlink(temp_tar_path);
    if (sock_fd >= 0 && local_mtu != original_mtu) {
        struct ifreq ifr_restore;
        memset(&ifr_restore, 0, sizeof(ifr_restore));
        strncpy(ifr_restore.ifr_name, active_interface, IFNAMSIZ - 1);
        ifr_restore.ifr_mtu = original_mtu;
        ioctl(sock_fd, SIOCSIFMTU, &ifr_restore);
    }

    if (file_map != NULL && file_map != MAP_FAILED) munmap(file_map, total_bytes); 
    if (file_fd >= 0) close(file_fd);
    if (sock_fd >= 0) close(sock_fd);
    if (bitmap != NULL) free(bitmap);
    
    endwin(); 
    return 0;
}