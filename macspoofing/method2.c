//written by noob0x

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct ether_addr *mac_parser(char *mac_addr);

int main(int argc, char **argv) {

    if(getuid()){
        printf("run app as root user !\n");
        exit(0);
    }
    printf("Network interfaces : \n");
    system("ls /sys/class/net");

    printf("Enter interface name : ");
    char interface_name[15];
    scanf("%s",interface_name);getchar();
    char cmd[60];
    strcpy(cmd, "ifconfig ");
    strcat(cmd, interface_name);
    strcat(cmd, " down");
    system(cmd);
    printf("%s\n",cmd);
    memset(cmd, 0,sizeof(cmd));
    

    char mac_buf[20];
    //enter new mac addr
    printf("Enter new mac addr : ");getchar();
    fgets(mac_buf, 20, stdin);
    mac_buf[strcspn(mac_buf, "\n")] = 0;

    strcpy(cmd, "ifconfig ");
    strcat(cmd, interface_name);
    strcat(cmd, " hw");
    strcat(cmd, " ether ");
    strcat(cmd, mac_buf);
    system(cmd);
    printf("%s\n",cmd);
    memset(cmd, 0,sizeof(cmd));

    strcpy(cmd, "ifconfig ");
    strcat(cmd, interface_name);
    strcat(cmd, " up");
    system(cmd);
    printf("%s\n",cmd);
    printf("mac changed to %s\n",mac_buf);
	return 0;
}
