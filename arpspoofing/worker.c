#include "worker.h"

void* spoof_worker(void* data)
{
    WORKER_DATA* w_data = (WORKER_DATA*)data;
    while (1) {
        send_fake_arp_reply(
            w_data->interface_data,
            w_data->spoofed_ip,
            w_data->spoofed_mac,
            w_data->target_mac_addr,
            w_data->target_ip_addr
        );
        sleep(ARP_INTERVAL);
    }
    return NULL;
}
