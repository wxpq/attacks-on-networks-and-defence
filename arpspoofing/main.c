//written by noob0x
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"

#define COMMAND_BUFF_SIZE 15

int main() {

  if(getuid()){
    printf("run app as root user !\n");
    exit(0);
  }

  char cmd_buff[COMMAND_BUFF_SIZE];

  APP *app = (APP *)malloc(sizeof(APP));
  memset(app, 0, sizeof(APP));
  system("sysctl -w net.ipv4.ip_forward=1");
  system("clear");
  printf("Network interfaces : \n");
  system("ls /sys/class/net");
  printf("Enter interface name : ");
  char interface_name[15];
  scanf("%s",interface_name);getchar();
  app->interface = get_if_data(interface_name);
  app->message = "App ready !\n";
  init_sniff_node(app);
  
  //create buffer
  char gateway_ip_buf[20];
  char gateway_mac_buf[20];

  //get node ip addr
  printf("Enter gateway ip addr: ");
  fgets(gateway_ip_buf, 20, stdin);
  gateway_ip_buf[strcspn(gateway_ip_buf, "\n")] = 0;

  //get node mac addr
  printf("Enter gateway mac addr : ");
  fgets(gateway_mac_buf, 20, stdin);
  gateway_mac_buf[strcspn(gateway_mac_buf, "\n")] = 0;

  unsigned char gateway_mac[ETH_ALEN];
  memcpy(gateway_mac, mac_parser(gateway_mac_buf),ETH_ALEN);

  init_gateway_node(app, inet_addr(gateway_ip_buf), gateway_mac);

  // add some commands to app
  add_cmd(app, 0, "add", "add node to spoofed topology");
  add_cmd(app, 1, "connect", "connect two nodes");
  add_cmd(app, 2, "status", "dump nodes");
  add_cmd(app, 3, "rm", "remove node from spoofed topology");

  while (1) {
    system("clear");
    printf("message : %s%s%s",GREEN,app->message,NORMAL);
    app->message = "Enter Valid command!\n";
    printf("available commands :\n");
    for (int i = 0; i < NUM_COMMANDS; i++) {
      if (app->app_commands[i] != NULL) {
        printf("%d) %s\t%s\n", 
                app->app_commands[i]->cmd_id,
                app->app_commands[i]->cmd,
                app->app_commands[i]->cmd_description
        );
      }
    }
    printf("enter command: ");
    fgets(cmd_buff, COMMAND_BUFF_SIZE, stdin);
    cmd_buff[strcspn(cmd_buff, "\n")] = 0; // eat Enter
    //linear search
    int j = 0;
    while(j < NUM_COMMANDS) {
      if (app->app_commands[j] != NULL) {
        if (strcmp(cmd_buff, app->app_commands[j]->cmd) == 0) {
          execute_cmd(app,app->app_commands[j]->cmd_id);
          memset(cmd_buff, 0, sizeof(cmd_buff));
          break;
        }
      }
      j++;
    }
  }
  return 0;
}
//written by noob0x
