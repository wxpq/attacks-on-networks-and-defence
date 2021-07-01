#include <stdio.h>
#include <stdlib.h>
#include "worker.h"

//number of commands
#define NUM_COMMANDS 4

//maximum number of nodes
#define MAX_NODE 5

//output colors
#define NORMAL  "\x1B[0m"
#define RED     "\x1B[31m"
#define GREEN   "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define BLUE    "\x1B[34m"
#define MAGNETA "\x1B[35m"
#define CYAN    "\x1B[36m"
#define WHIRE   "\x1B[37m"


//define node struct (node => every device in network)
#define NODE_DUMP "\n=======================\n| device id:%s%d%s\n| ip:%s\n| mac:%s\n| conn--> %s%d%s \n=======================\n"
#define MAIN_NODE_DUMP "\n======\x1B[32msniffer node\x1B[0m=====\n| device id:%s%d%s\n| ip:%s\n| mac:%s\n| %s%d%s <--conn--> %s%d%s\n=======================\n"
#define GATE_NODE_DUMP "\n=======\x1B[31mgate node\x1B[0m=======\n| device id:%s%d%s\n| ip:%s\n| mac:%s\n| conn--> %s%d%s\n=======================\n"

typedef struct
{
    int node_id;
    unsigned int node_ip;
    unsigned char node_mac[ETH_ALEN];
    struct {
            int node_id;
            unsigned int node_ip;
            unsigned char node_mac[ETH_ALEN];
    }left_conn;
    struct {
            int node_id;
            unsigned int node_ip;
            unsigned char node_mac[ETH_ALEN];
    } right_conn;
} SNIFF_NODE;

typedef struct
{
    int node_id;
    unsigned int node_ip;
    unsigned char node_mac[ETH_ALEN];
    struct {
            int node_id;
            unsigned int node_ip;
            unsigned char node_mac[ETH_ALEN];
    } conn;
} NODE;

//init nodes
NODE* node_init(int node_id,unsigned int ip_addr,unsigned char* mac_addr);
SNIFF_NODE* sniff_node_init(int node_id,unsigned int ip_addr,unsigned char* mac_addr);

void set_left_node(SNIFF_NODE* sniff_node,NODE* conn_node);

void set_right_node(SNIFF_NODE* sniff_node,NODE* conn_node);

//dump node info
void node_dump(NODE* node,char* node_type);
void sniff_node_dump(SNIFF_NODE* node);
//define some structs for app
typedef struct{
    int cmd_id;
    char* cmd;
    char* cmd_description;
} APP_CMD;

//define function for adding command to app
APP_CMD* declare_cmd(char* cmd_name,char* cmd_description);

typedef struct
{
    APP_CMD* app_commands[NUM_COMMANDS];
    SNIFF_NODE* main_node;
    NODE* active_nodes[MAX_NODE];
    struct {
        pthread_t thread_id;
        WORKER_DATA w_data;
    } right_worker;
    struct {
        pthread_t thread_id;
        WORKER_DATA w_data;
    } left_worker;
    IF_DATA* interface;
    char* message;
} APP;
void add_cmd(APP* app,int cmd_id,char* cmd_name,char* cmd_description);

void remove_node(APP* app,int node_id);

void execute_cmd(APP* app,int cmd_id);

void init_sniff_node(APP* app);

void init_gateway_node(APP* app,unsigned int ip_addr,unsigned char * mac_addr);

void start_worker(APP* app,char* selector,unsigned int spoofed_ip,unsigned char *spoofed_mac, unsigned char *target_mac_addr,unsigned int target_ip_addr);

void stop_worker(APP* app,char* selector);