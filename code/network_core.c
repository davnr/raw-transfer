/*
 * File: network_core.c
 * Description: Implements network interface discovery (excluding Wi-Fi) and 
 * sets up the AF_PACKET raw socket, attempting to negotiate Jumbo Frames.
 */

#include "network_core.h"
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/if_ether.h>
// Scans system network interfaces. Excludes wireless interfaces because
// injecting custom L2 frames into Wi-Fi often requires monitor mode.
void discover_interfaces(AppContext *ctx) {
    struct ifaddrs *ifaddr, *ifa;
    ctx->interface_count = 0;

    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            
            // Look only for physical/packet level interfaces
            if (ifa->ifa_addr->sa_family == AF_PACKET && ctx->interface_count < 10) {
                // Check if it's a wireless interface by looking at the sysfs path
                char sysfs_path[256];
                snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/wireless", ifa->ifa_name);
                if (access(sysfs_path, F_OK) == 0) continue; // Skip if it's Wi-Fi
                
                strncpy(ctx->interface_list[ctx->interface_count], ifa->ifa_name, IFNAMSIZ - 1);
                ctx->interface_count++;
            }
        }
        freeifaddrs(ifaddr);
    }
}

// Binds a raw socket to the selected interface and configures MTU
int setup_network(AppContext *ctx) {
    // Open a RAW socket allowing us to forge the Ethernet Header manually
    ctx->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sock_fd < 0) return -1;
    
    //Directly access the hardware, bupasses the linux queue
    int qdisc_bypass = 1;
    setsockopt(ctx->sock_fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));

    // Increase the socket receive buffer to handle extreme speeds (32MB)
    int rcvbuf = 32 * 1024 * 1024; 
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ctx->active_interface); 
    
    // Get Interface Index
    if (ioctl(ctx->sock_fd, SIOCGIFINDEX, &ifr) < 0) return -2;
    int ifindex = ifr.ifr_ifindex;

    // Get my MAC Address
    if (ioctl(ctx->sock_fd, SIOCGIFHWADDR, &ifr) < 0) return -3;
    memcpy(ctx->my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get current MTU (to restore it later)
    if (ioctl(ctx->sock_fd, SIOCGIFMTU, &ifr) == 0) ctx->original_mtu = ifr.ifr_mtu;
    else ctx->original_mtu = 1500; 

    // Attempt to set Jumbo Frames (MTU 9000) for better throughput
    ifr.ifr_mtu = 9000;
    if (ioctl(ctx->sock_fd, SIOCSIFMTU, &ifr) == 0) ctx->local_mtu = 9000;
    else ctx->local_mtu = ctx->original_mtu; 

    // Bind socket to the specific interface hardware
    memset(&ctx->sll, 0, sizeof(ctx->sll));
    ctx->sll.sll_family = AF_PACKET;
    ctx->sll.sll_protocol = htons(ETH_P_ALL);
    ctx->sll.sll_ifindex = ifindex;
    if (bind(ctx->sock_fd, (struct sockaddr *)&ctx->sll, sizeof(ctx->sll)) < 0) return -4;
    
    return 0;
}
