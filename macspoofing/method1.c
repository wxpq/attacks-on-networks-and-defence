//written by noob0x

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

struct ether_addr *mac_parser(char *mac_addr);

int main(int argc, char **argv) {

    if(getuid()){
        printf("run app as root user !\n");
        exit(0);
    }

    system("clear");
    printf("Network interfaces : \n");
    system("ls /sys/class/net");

    printf("Enter interface name : ");
    char interface_name[15];
    scanf("%s",interface_name);getchar();

    char mac_buf[20];
    //enter new mac addr
    printf("Enter new mac addr : ");
    fgets(mac_buf, 20, stdin);
    mac_buf[strcspn(mac_buf, "\n")] = 0;

	struct ifreq ifr;
	int sock_fd;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("cannot create socket");
        exit(0);
    }

    //get parsed mac addr
    unsigned char parsed_mac_addr[ETH_ALEN];
    memcpy(parsed_mac_addr, mac_parser(mac_buf), ETH_ALEN);

	strcpy(ifr.ifr_name, interface_name);
	ifr.ifr_hwaddr.sa_data[0] = parsed_mac_addr[0];
	ifr.ifr_hwaddr.sa_data[1] = parsed_mac_addr[1];
	ifr.ifr_hwaddr.sa_data[2] = parsed_mac_addr[2];
	ifr.ifr_hwaddr.sa_data[3] = parsed_mac_addr[3];
	ifr.ifr_hwaddr.sa_data[4] = parsed_mac_addr[4];
	ifr.ifr_hwaddr.sa_data[5] = parsed_mac_addr[5];
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    if (ioctl(sock_fd, SIOCSIFHWADDR, &ifr) == -1){
       perror("ioctl() get mac");
       exit(1);
    }
    printf("mac changed to %s\n",mac_buf);

    close(sock_fd);
	return 0;
}

struct ether_addr *mac_parser(char *mac_addr) {
  struct ether_addr *ethaddr = NULL;
  ethaddr = ether_aton(mac_addr);
  if (NULL == ethaddr) {
    printf("Invalid Ethernet destination address.\n");
    exit(0);
  }
  return ethaddr;
}