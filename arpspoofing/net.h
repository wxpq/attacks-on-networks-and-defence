#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy(), memset(), and memcpy()
#include <sys/socket.h>       //socket()
#include <netinet/in.h>       // IPPROTO_RAW
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>     //ether_aton()


/* Ethernet frame header length */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/*  The length of the entire arp structure */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/*  Ethernet + entire arp structure length */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
/*  IP address length */
#define IP_ADDR_LEN 4

//define functions

typedef struct
{
    char if_name[15];
    int index;
    unsigned int ip_addr;
    unsigned char mac_addr[ETH_ALEN];
} IF_DATA;

IF_DATA* get_if_data(char* if_name);

struct ether_addr* mac_parser(char* mac_addr);

struct ether_arp *generate_arp_packet(const unsigned char *src_mac_addr,unsigned int src_ip,unsigned int target_ip_addr,unsigned char *target_mac_addr);

void send_fake_arp_reply(IF_DATA* if_data, unsigned int spoofed_ip,unsigned char *spoofed_mac, unsigned char *target_mac_addr,unsigned int target_ip_addr);

