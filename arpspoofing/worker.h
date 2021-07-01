#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "net.h"

#define ARP_INTERVAL 8

typedef struct {
    IF_DATA* interface_data;
    unsigned int spoofed_ip;
    unsigned char spoofed_mac[ETH_ALEN];
    unsigned char target_mac_addr[ETH_ALEN];
    unsigned int target_ip_addr;
} WORKER_DATA;

void* spoof_worker();