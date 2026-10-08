/*
 * File: raw_transfer.c
 * Descrizione: Applicazione TUI in C per il trasferimento raw di Livello 2 (Data Link) ad altissima velocità.
 *              Il programma bypassa lo stack TCP/IP per comunicare direttamente con la scheda di rete.
 *              Utilizza tecniche avanzate come il Batching delle Syscall (sendmmsg/recvmmsg) per
 *              minimizzare l'overhead della CPU, il memory mapping (mmap) per l'I/O su disco,
 *              il recupero errori tramite Bulk NACK e la negoziazione dinamica dei Jumbo Frames (MTU 9000).
 *              Alla chiusura, ripristina automaticamente lo stato originale della scheda di rete.
 */

#define _GNU_SOURCE // Necessario per sbloccare le system call avanzate di Linux (sendmmsg/recvmmsg)

// ==============================================================================
// LIBRERIE
// ==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>              // Operazioni sui file (open, O_RDONLY, ecc.)
#include <sys/stat.h>           
#include <sys/ioctl.h>          // Controllo dispositivi I/O (per leggere/scrivere l'MTU)
#include <sys/socket.h>         // Fondamenta per le comunicazioni di rete
#include <net/if.h>             // Interfacce di rete
#include <arpa/inet.h>          // Conversioni di byte order (htons, ntohl, ecc.)
#include <linux/if_packet.h>    // Strutture per socket AF_PACKET (Livello 2)
#include <netinet/if_ether.h>   // Header Ethernet
#include <ifaddrs.h>            // Iterazione sulle interfacce di rete del PC
#include <sys/mman.h>           // Memory mapping (mmap)
#include <sys/time.h>           // Calcolo dei millisecondi per la TUI
#include <ncurses.h>            // Interfaccia grafica da terminale
#include <errno.h>

// ==============================================================================
// COSTANTI GLOBALI
// ==============================================================================
#define CUSTOM_ETHERTYPE 0x88B5     // EtherType sperimentale: ignorato dal SO, non interferisce con internet
#define FILE_TO_SEND "test.dat"     // File di input letto da chi Invia
#define FILE_TO_SAVE "ricevuto.dat" // File di output scritto da chi Riceve

// Codici operativi (Opcode) per distinguere il tipo di pacchetto
#define OP_PING 0   // Inviato dal Sender per annunciare il trasferimento
#define OP_PONG 1   // Risposta del Receiver per confermare la connessione
#define OP_DATA 2   // Pacchetto contenente un frammento del file
#define OP_NACK 3   // Pacchetto contenente le sequenze mancanti (Buchi)
#define OP_DONE 4   // Trasferimento completato con successo

#define BATCH_SIZE 256              // Numero di pacchetti inviati/ricevuti in una singola operazione
#define MAX_JUMBO_PAYLOAD 8950      // Grandezza massima del payload supportata (per MTU fino a ~9000)

// ==============================================================================
// DEFINIZIONE DEL PROTOCOLLO (STRUTTURE DATI)
// Nota: __attribute__((packed)) è vitale. Dice al compilatore di non inserire
// byte vuoti (padding) tra le variabili per allinearle in memoria. Così facendo,
// la struttura in RAM è identica a come viaggerà sul cavo di rete.
// ==============================================================================

// Header inserito in tutti i pacchetti per identificarne il contenuto
struct file_meta {
    uint8_t opcode;      // Tipo di pacchetto (PING, DATA, ecc.)
    uint32_t seq_num;    // Numero di sequenza del frammento (1, 2, 3...)
    uint16_t data_size;  // Quanti byte utili ci sono in questo frammento
    uint8_t is_eof;      // Flag (1) se è l'ultimo frammento del file
} __attribute__((packed));

// Payload del pacchetto di PING (Sender -> Receiver)
struct handshake_info {
    uint64_t total_bytes; // Dimensione totale del file da trasferire
    uint16_t sender_mtu;  // L'MTU massimo supportato dalla scheda di chi invia
} __attribute__((packed));

// Payload del pacchetto di PONG (Receiver -> Sender)
struct handshake_response {
    uint16_t negotiated_mtu;  // L'MTU definitivo (il minimo tra chi invia e chi riceve)
    uint32_t total_fragments; // Numero totale di pacchetti calcolati in base all'MTU
} __attribute__((packed));

// Il "Frame Ethernet" customizzato. Questa è l'esatta struttura dei byte sul cavo
struct custom_frame {
    unsigned char dest_mac[6];                 // Indirizzo MAC di destinazione
    unsigned char src_mac[6];                  // Indirizzo MAC sorgente
    unsigned short ether_type;                 // Tipo di protocollo (0x88B5)
    struct file_meta meta;                     // Il nostro header meta
    unsigned char payload[MAX_JUMBO_PAYLOAD];  // I dati veri e propri
} __attribute__((packed));

// Payload del pacchetto NACK (Negative Acknowledgment)
// Usato dal ricevitore per chiedere la ritrasmissione dei pacchetti persi.
struct nack_payload {
    uint16_t count;          // Quanti buchi sono stati rilevati
    uint32_t sequences[349]; // Array dei numeri di sequenza da ritrasmettere
} __attribute__((packed));

// Macchina a stati per gestire il flusso asincrono dell'applicazione
typedef enum {
    STATE_SELECT_INTERFACE,
    STATE_IDLE,
    STATE_RECEIVER_WAITING_PING,
    STATE_RECEIVER_RECEIVING,
    STATE_SENDER_SENDING_PING,
    STATE_SENDER_WAITING_PONG,
    STATE_SENDER_TRANSFERRING,
    STATE_SENDER_WAITING_NACK, 
    STATE_DONE,
    STATE_ERROR
} AppState;

// ==============================================================================
// FUNZIONI DI SUPPORTO E RETE
// ==============================================================================

// Restituisce il timestamp attuale in millisecondi (usato per limitare gli FPS della UI)
long long current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

// Configura il socket di basso livello, recupera gli indirizzi MAC e forza l'MTU
int setup_network(const char *ifname, int *sock_fd, unsigned char *my_mac, struct sockaddr_ll *sll, int *local_mtu, int *original_mtu) {
    
    // 1. Crea un Socket Raw al Livello 2.
    // ETH_P_ALL permette di catturare e inviare QUALSIASI frame Ethernet.
    *sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*sock_fd < 0) return -1;

    // Aumenta il buffer del kernel a 32MB per evitare cadute di pacchetti
    // se il programma sta disegnando la UI e non fa in tempo a leggere la rete.
    int rcvbuf = 32 * 1024 * 1024; 
    setsockopt(*sock_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // Struttura usata per parlare con il driver della scheda di rete (ioctl)
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    // Recupera l'indice della scheda di rete per fare il binding
    if (ioctl(*sock_fd, SIOCGIFINDEX, &ifr) < 0) return -2;
    int ifindex = ifr.ifr_ifindex;

    // Recupera l'indirizzo MAC fisico della nostra scheda
    if (ioctl(*sock_fd, SIOCGIFHWADDR, &ifr) < 0) return -3;
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Salva l'MTU originale prima di modificarlo
    if (ioctl(*sock_fd, SIOCGIFMTU, &ifr) == 0) {
        *original_mtu = ifr.ifr_mtu;
    } else {
        *original_mtu = 1500; 
    }

    // Tenta di forzare l'MTU a 9000 (Jumbo Frames) per la massima velocità
    ifr.ifr_mtu = 9000;
    if (ioctl(*sock_fd, SIOCSIFMTU, &ifr) == 0) {
        *local_mtu = 9000;
    } else {
        *local_mtu = *original_mtu; 
    }

    // Associa (Bind) il socket alla scheda di rete selezionata
    memset(sll, 0, sizeof(*sll));
    sll->sll_family = AF_PACKET;
    sll->sll_protocol = htons(ETH_P_ALL);
    sll->sll_ifindex = ifindex;
    if (bind(*sock_fd, (struct sockaddr *)sll, sizeof(*sll)) < 0) return -4;
    
    return 0;
}

// ==============================================================================
// MAIN: CUORE DELL'APPLICAZIONE
// ==============================================================================
int main() {
    
    // --- Inizializzazione Interfaccia Ncurses ---
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE); // Rende non-bloccante getch() così il loop gira sempre
    curs_set(0);

    // --- Ricerca Schede di Rete ---
    char interface_list[10][IFNAMSIZ];
    int interface_count = 0;
    int current_selection = 0;
    char active_interface[IFNAMSIZ] = "";

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            
            // Cerca interfacce di Livello 2 ed esclude esplicitamente le schede Wi-Fi
            // (Il Wi-Fi a basso livello è troppo instabile per questo approccio)
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

    // --- Variabili di Stato Globali ---
    int sock_fd = -1;
    unsigned char my_mac[6], target_mac[6];
    struct sockaddr_ll sll;
    
    int file_fd = -1;                       
    uint64_t total_bytes = 1;               
    uint64_t processed_bytes = 0;           
    uint32_t total_fragments = 0;           
    uint32_t sequence = 1;                  
    uint8_t *bitmap = NULL;     // Traccia i pacchetti ricevuti/mancanti            
    uint8_t *file_map = NULL;   // Puntatore alla RAM che "riflette" il file su disco            
    
    // Configurazione dell'MTU
    int local_mtu = 1500;
    int original_mtu = 1500;
    int negotiated_mtu = 1500;
    int neg_payload_size = 1400;
    
    // --- Allocazione Array per Syscall Batching ---
    // Queste strutture sono statiche (allocate nel segmento BSS) per evitare 
    // di appesantire lo Stack o rallentare il programma con malloc costanti.
    static struct mmsghdr rx_msgs[BATCH_SIZE];
    static struct iovec rx_iov[BATCH_SIZE];
    static struct custom_frame rx_frames[BATCH_SIZE];
    static struct sockaddr_ll remote_sll_arr[BATCH_SIZE];

    static struct mmsghdr tx_msgs[BATCH_SIZE];
    static struct iovec tx_iov[BATCH_SIZE];
    static struct custom_frame tx_frames[BATCH_SIZE];
    
    // Pre-compiliamo gli array di ricezione per le syscall
    memset(rx_msgs, 0, sizeof(rx_msgs));
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

    // ==============================================================================
    // MAIN LOOP: GESTIONE EVENTI ASINCRONI (UI + NETWORK)
    // ==============================================================================
    while (running) {
        
        // --- 1. Gestione Input Utente ---
        int ch = getch();
        if (ch != ERR) {
            if (ch == 'q' || ch == 'Q') {
                running = 0; // Avvia la procedura di uscita
            } 
            else if (state == STATE_SELECT_INTERFACE) {
                if ((ch == KEY_UP || ch == 'k' || ch == 'K') && current_selection > 0) {
                    current_selection--;
                }
                else if ((ch == KEY_DOWN || ch == 'j' || ch == 'J') && current_selection < interface_count - 1) {
                    current_selection++;
                }
                else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) { 
                    strncpy(active_interface, interface_list[current_selection], IFNAMSIZ);
                    // Inizializza il socket e legge l'MTU
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
                file_fd = open(FILE_TO_SEND, O_RDONLY);
                if (file_fd < 0) {
                    state = STATE_ERROR;
                    snprintf(status_msg, sizeof(status_msg), "Errore: File '%s' non trovato.", FILE_TO_SEND);
                } else {
                    // Calcola le dimensioni del file
                    total_bytes = lseek(file_fd, 0, SEEK_END); 
                    lseek(file_fd, 0, SEEK_SET);               
                    state = STATE_SENDER_SENDING_PING;
                    snprintf(status_msg, sizeof(status_msg), "Ricerca ricevitore...");
                }
            }
        }

        // ==============================================================================
        // LATO RICEVITORE
        // ==============================================================================
        if (state == STATE_RECEIVER_WAITING_PING || state == STATE_RECEIVER_RECEIVING) {
            
            while (1) {
                // recvmmsg estrae fino a 256 pacchetti dal kernel in un colpo solo.
                // MSG_DONTWAIT impedisce il blocco se non c'è traffico.
                int vlen = recvmmsg(sock_fd, rx_msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
                if (vlen < 0) break; // Coda vuota
                
                // Processiamo tutti i pacchetti ricevuti in blocco
                for (int i = 0; i < vlen; i++) {
                    struct custom_frame *rx_frame = &rx_frames[i];
                    socklen_t sll_len = rx_msgs[i].msg_hdr.msg_namelen;
                    
                    // Controlla se il pacchetto appartiene al nostro protocollo
                    if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                        
                        // FASE 1: Handshake (Ricezione del PING)
                        if (state == STATE_RECEIVER_WAITING_PING && rx_frame->meta.opcode == OP_PING) {
                            memcpy(target_mac, rx_frame->src_mac, 6);
                            
                            struct handshake_info *hi = (struct handshake_info *)rx_frame->payload;
                            total_bytes = hi->total_bytes;
                            uint16_t sender_mtu = ntohs(hi->sender_mtu);
                            
                            // Negoziazione: prendiamo l'MTU più basso tra i due PC
                            negotiated_mtu = (sender_mtu < local_mtu) ? sender_mtu : local_mtu;
                            neg_payload_size = negotiated_mtu - sizeof(struct file_meta);
                            if (neg_payload_size > MAX_JUMBO_PAYLOAD) neg_payload_size = MAX_JUMBO_PAYLOAD;
                            
                            total_fragments = (total_bytes + neg_payload_size - 1) / neg_payload_size;
                            bitmap = calloc(total_fragments + 1, sizeof(uint8_t));
                            
                            // Prepariamo il file mmap su cui salvare i dati ad altissima velocità
                            file_fd = open(FILE_TO_SAVE, O_RDWR | O_CREAT | O_TRUNC, 0644);
                            ftruncate(file_fd, total_bytes); 
                            file_map = mmap(NULL, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, file_fd, 0);
                            
                            // Prepariamo la risposta (PONG)
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
                        
                        // FASE 2: Ricezione Dati (DATA)
                        else if (state == STATE_RECEIVER_RECEIVING && rx_frame->meta.opcode == OP_DATA) {
                            uint32_t seq = ntohl(rx_frame->meta.seq_num);
                            uint16_t payload_size = ntohs(rx_frame->meta.data_size);
                            
                            // Se il pacchetto è valido e non lo abbiamo già ricevuto
                            if (seq <= total_fragments && bitmap[seq] == 0) {
                                // Calcoliamo la posizione esatta in base al numero di sequenza
                                off_t offset = (off_t)(seq - 1) * neg_payload_size;
                                
                                // Copiamo i dati dal pacchetto direttamente nella RAM (che kernel rifletterà sul disco)
                                if (file_map != NULL && (offset + payload_size) <= total_bytes) {
                                    memcpy(file_map + offset, rx_frame->payload, payload_size);
                                }
                                
                                bitmap[seq] = 1; // Segniamo il frammento come ricevuto
                                processed_bytes += payload_size;
                                
                                // FASE 3: Completamento
                                if (processed_bytes >= total_bytes) {
                                    // Avvisiamo il mittente che abbiamo ricevuto tutto
                                    struct custom_frame tx_done;
                                    memset(&tx_done, 0, sizeof(tx_done));
                                    memcpy(tx_done.dest_mac, target_mac, 6);
                                    memcpy(tx_done.src_mac, my_mac, 6);
                                    tx_done.ether_type = htons(CUSTOM_ETHERTYPE);
                                    tx_done.meta.opcode = OP_DONE;
                                    sendto(sock_fd, &tx_done, 14 + sizeof(struct file_meta), 0, (struct sockaddr *)&remote_sll_arr[i], sll_len);

                                    // Chiudiamo il file e terminiamo
                                    munmap(file_map, total_bytes);
                                    file_map = NULL;
                                    close(file_fd);
                                    file_fd = -1;
                                    state = STATE_DONE;
                                    snprintf(status_msg, sizeof(status_msg), "Trasferimento completato con successo.");
                                    break; 
                                }
                            }
                        }
                    }
                } 
            } 

            // FASE 4: Gestione Errori (NACK)
            // Se stiamo ricevendo dati, ogni tanto controlliamo se manca qualcosa (Selective Repeat).
            if (state == STATE_RECEIVER_RECEIVING) {
                static int nack_timer = 0;
                if (nack_timer++ >= 15) { // Contatore che rallenta i check per non spammare
                    nack_timer = 0;
                    
                    struct custom_frame nack_frame;
                    memset(&nack_frame, 0, sizeof(nack_frame));
                    memcpy(nack_frame.dest_mac, target_mac, 6);
                    memcpy(nack_frame.src_mac, my_mac, 6);
                    nack_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                    nack_frame.meta.opcode = OP_NACK;
                    
                    struct nack_payload *np = (struct nack_payload *)nack_frame.payload;
                    np->count = 0;
                    int total_requested = 0;

                    // Scansioniamo la bitmap per cercare sequenze mancanti (valore 0)
                    for (uint32_t i = 1; i <= total_fragments; i++) {
                        if (bitmap[i] == 0) { 
                            np->sequences[np->count++] = htonl(i); 
                            total_requested++;
                            
                            // Se riempiamo un pacchetto NACK, lo inviamo e ripartiamo col successivo
                            if (np->count == 349) {
                                sendto(sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 0, (struct sockaddr *)&sll, sizeof(sll));
                                np->count = 0;
                                usleep(50); 
                            }
                            
                            // Limite di sicurezza per non ingolfare la rete con troppe richieste NACK
                            if (total_requested >= 5000) break; 
                        }
                    }
                    
                    // Inviamo i residui
                    if (np->count > 0) {
                        sendto(sock_fd, &nack_frame, 14 + sizeof(struct file_meta) + sizeof(uint16_t) + (np->count * sizeof(uint32_t)), 0, (struct sockaddr *)&sll, sizeof(sll));
                    }
                    
                    if (total_requested > 0) {
                        snprintf(status_msg, sizeof(status_msg), "Recupero di %d frammenti...", total_requested);
                    }
                }
            }
        }

        // ==============================================================================
        // LATO MITTENTE
        // ==============================================================================
        
        // FASE 1: Invia il PING (Broadcast) per farsi notare dal ricevitore
        if (state == STATE_SENDER_SENDING_PING) {
            struct custom_frame ping;
            memset(&ping, 0, sizeof(ping));
            memset(ping.dest_mac, 0xFF, 6); // Broadcast MAC Address
            memcpy(ping.src_mac, my_mac, 6);
            ping.ether_type = htons(CUSTOM_ETHERTYPE);
            ping.meta.opcode = OP_PING;
            
            struct handshake_info hi;
            hi.total_bytes = total_bytes;
            hi.sender_mtu = htons((uint16_t)local_mtu);
            memcpy(ping.payload, &hi, sizeof(struct handshake_info));
            
            sendto(sock_fd, &ping, 14 + sizeof(struct file_meta) + sizeof(struct handshake_info), 0, (struct sockaddr *)&sll, sizeof(sll));
            state = STATE_SENDER_WAITING_PONG;
        }
        
        // FASE 2: Attende il PONG con i dati negoziati
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
                    sequence = 1;
                    processed_bytes = 0;
                    state = STATE_SENDER_TRANSFERRING;
                    
                    snprintf(status_msg, sizeof(status_msg), "Trasferimento dati in corso...");
                }
            }
        }
        
        // FASE 3: Trasferimento (Saturazione Linea a pacchetti di 256 alla volta)
        // Il mittente usa un approccio "fire and forget". Non aspetta conferme,
        // carica semplicemente i buffer di rete alla massima velocità.
        else if (state == STATE_SENDER_TRANSFERRING) {
            int packets_per_cycle = 10000; 
            int sent_this_cycle = 0;
            uint8_t eof_reached = 0;

            while (sent_this_cycle < packets_per_cycle && !eof_reached) {
                int batch_count = 0;
                memset(tx_msgs, 0, sizeof(tx_msgs));

                // Compilazione del batch
                for (int i = 0; i < BATCH_SIZE; i++) {
                    memset(&tx_frames[i], 0, sizeof(struct custom_frame));
                    memcpy(tx_frames[i].dest_mac, target_mac, 6);
                    memcpy(tx_frames[i].src_mac, my_mac, 6);
                    tx_frames[i].ether_type = htons(CUSTOM_ETHERTYPE);
                    tx_frames[i].meta.opcode = OP_DATA;
                    
                    // Legge sequenzialmente dal file
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
                        
                        processed_bytes += bytes_read;
                        batch_count++;

                        if (tx_frames[i].meta.is_eof) {
                            eof_reached = 1;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                // Invio in batch (1 solo context switch per 256 frame)
                if (batch_count > 0) {
                    sendmmsg(sock_fd, tx_msgs, batch_count, 0); 
                    sent_this_cycle += batch_count;
                } else {
                    break;
                }
            }
            
            // Finito il file, attende eventuali segnalazioni di errori
            if (eof_reached) {
                state = STATE_SENDER_WAITING_NACK;
                snprintf(status_msg, sizeof(status_msg), "Verifica integrità in corso...");
            }
        }
        
        // FASE 4: Attesa NACK e Ritrasmissione
        // Il mittente ascolta eventuali NACK cumulativi dal ricevitore e li soddisfa
        else if (state == STATE_SENDER_WAITING_NACK) {
            while (1) {
                unsigned char buffer[65536];
                ssize_t rx_size = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);
                if (rx_size < 0) break; 
                
                struct custom_frame *rx_frame = (struct custom_frame *)buffer;
                if (ntohs(rx_frame->ether_type) == CUSTOM_ETHERTYPE) {
                    
                    // Ricezione dei buchi
                    if (rx_frame->meta.opcode == OP_NACK) {
                        struct nack_payload *np = (struct nack_payload *)rx_frame->payload;
                        uint16_t count = np->count;
                        
                        for(int i = 0; i < count; i++) {
                            uint32_t missing_seq = ntohl(np->sequences[i]);
                            
                            struct custom_frame data_frame;
                            memset(&data_frame, 0, sizeof(data_frame));
                            memcpy(data_frame.dest_mac, target_mac, 6);
                            memcpy(data_frame.src_mac, my_mac, 6);
                            data_frame.ether_type = htons(CUSTOM_ETHERTYPE);
                            data_frame.meta.opcode = OP_DATA;
                            data_frame.meta.seq_num = htonl(missing_seq);
                            
                            // "pread" permette di leggere dal file da uno specifico offset
                            // senza modificare la posizione globale del cursore del file.
                            off_t offset = (off_t)(missing_seq - 1) * neg_payload_size;
                            ssize_t bytes_read = pread(file_fd, data_frame.payload, neg_payload_size, offset);
                            
                            if (bytes_read > 0) {
                                data_frame.meta.data_size = htons((uint16_t)bytes_read);
                                data_frame.meta.is_eof = 0; // L'eof l'abbiamo già mandato
                                sendto(sock_fd, &data_frame, 14 + sizeof(struct file_meta) + bytes_read, 0, (struct sockaddr *)&sll, sizeof(sll));
                            }
                        }
                    }
                    // Termine
                    else if (rx_frame->meta.opcode == OP_DONE) {
                        close(file_fd);
                        file_fd = -1;
                        state = STATE_DONE;
                        snprintf(status_msg, sizeof(status_msg), "Trasferimento completato con successo.");
                        break; 
                    }
                }
            }
        }

        // ==============================================================================
        // GESTIONE INTERFACCIA UTENTE (TUI NCURSES)
        // Aggiorna lo schermo a un massimo di ~60 FPS per non stressare la CPU.
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
                    if (i == current_selection) {
                        attron(A_REVERSE); 
                        mvprintw(6 + i, 6, " > %s ", interface_list[i]);
                        attroff(A_REVERSE);
                    } else {
                        mvprintw(6 + i, 6, "   %s ", interface_list[i]);
                    }
                }
            } 
            else {
                // Nasconde il valore negoziato dell'MTU se non c'è ancora stato l'handshake
                if (state == STATE_RECEIVER_RECEIVING || state == STATE_SENDER_TRANSFERRING || 
                    state == STATE_SENDER_WAITING_NACK || state == STATE_DONE) {
                    mvprintw(4, 4, "Interfaccia: %s | MTU Rete: %d", active_interface, negotiated_mtu);
                } else {
                    mvprintw(4, 4, "Interfaccia: %s | MTU Rete: (In attesa)", active_interface);
                }
                
                mvprintw(5, 4, "Stato: %s", status_msg);
                
                if (state != STATE_ERROR) {
                    mvprintw(7, 4, "Mio MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
                             my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
                }
                
                // Disegna i dati e la barra di progresso solo durante/dopo il trasferimento
                if (state == STATE_SENDER_TRANSFERRING || state == STATE_RECEIVER_RECEIVING || 
                    state == STATE_DONE || state == STATE_SENDER_WAITING_NACK) {
                    mvprintw(8, 4, "MAC Target: %02x:%02x:%02x:%02x:%02x:%02x", 
                             target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
                
                    int bar_width = 40;
                    int filled = (total_bytes > 0) ? (processed_bytes * bar_width) / total_bytes : 0;
                    
                    mvprintw(10, 4, "[");
                    for (int i = 0; i < bar_width; i++) addch(i < filled ? '#' : '-');
                    printw("] %d%% (%llu/%llu byte)", 
                           (total_bytes > 0) ? (int)((processed_bytes * 100) / total_bytes) : 0, 
                           (unsigned long long)processed_bytes, (unsigned long long)total_bytes);
                }
            }

            refresh();
            last_draw_time = now; 
        }

        // Se non stiamo trasferendo pesantemente, mettiamo a dormire il processo per 16ms
        // per ridurre il consumo di CPU e batteria durante i momenti di attesa/idle.
        if (state != STATE_SENDER_TRANSFERRING && state != STATE_RECEIVER_RECEIVING && state != STATE_SENDER_WAITING_NACK) {
            usleep(16000); 
        }
    }

    // ==============================================================================
    // CLEANUP E CHIUSURA (Ripristino risorse del sistema operativo)
    // ==============================================================================
    
    // Ripristino dell'MTU al valore di partenza (per non lasciare scombinato il networking locale)
    if (sock_fd >= 0 && local_mtu != original_mtu) {
        struct ifreq ifr_restore;
        memset(&ifr_restore, 0, sizeof(ifr_restore));
        strncpy(ifr_restore.ifr_name, active_interface, IFNAMSIZ - 1);
        ifr_restore.ifr_mtu = original_mtu;
        ioctl(sock_fd, SIOCSIFMTU, &ifr_restore);
    }

    // Chiusura dei vari descrittori e rilascio memoria RAM
    if (file_map != NULL && file_map != MAP_FAILED) munmap(file_map, total_bytes); 
    if (file_fd >= 0) close(file_fd);
    if (sock_fd >= 0) close(sock_fd);
    if (bitmap != NULL) free(bitmap);
    
    endwin(); // Chiude la modalità TUI restituendo il controllo alla console normale
    
    return 0;
}