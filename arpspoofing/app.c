#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "app.h"

//init node
NODE* node_init(int node_id,unsigned int ip_addr,unsigned char* mac_addr){
    NODE* node = (NODE*)malloc(sizeof(NODE));
    node->node_id = node_id;
    node->node_ip = ip_addr;
    memcpy(node->node_mac, mac_addr, ETH_ALEN);
    node->conn.node_id = -1;
    return node;
}

SNIFF_NODE* sniff_node_init(int node_id,unsigned int ip_addr,unsigned char* mac_addr){
    SNIFF_NODE* node = (SNIFF_NODE*)malloc(sizeof(SNIFF_NODE));
    node->node_id = node_id;
    node->node_ip = ip_addr;
    memcpy(node->node_mac, mac_addr, ETH_ALEN);
    node->left_conn.node_id = -1;
    node->right_conn.node_id = -1;
    return node;
}

void set_left_node(SNIFF_NODE* sniff_node,NODE* conn_node){
    sniff_node->left_conn.node_id = conn_node->node_id;
    sniff_node->left_conn.node_ip = conn_node->node_ip;
    memcpy(sniff_node->left_conn.node_mac, conn_node->node_mac,ETH_ALEN);

    conn_node->conn.node_id = sniff_node->node_id;
    conn_node->conn.node_ip = sniff_node->node_ip;
    memcpy(conn_node->conn.node_mac, sniff_node->node_mac,ETH_ALEN);
}

void set_right_node(SNIFF_NODE* sniff_node,NODE* conn_node){
    sniff_node->right_conn.node_id = conn_node->node_id;
    sniff_node->right_conn.node_ip = conn_node->node_ip;
    memcpy(sniff_node->right_conn.node_mac, conn_node->node_mac,ETH_ALEN);

    conn_node->conn.node_id = sniff_node->node_id;
    conn_node->conn.node_ip = sniff_node->node_ip;
    memcpy(conn_node->conn.node_mac, sniff_node->node_mac,ETH_ALEN);
}

void remove_node(APP* app,int node_id){
    if (node_id == 1) {
        if (app->main_node->left_conn.node_id == node_id) {
            stop_worker(app, "left");
            stop_worker(app, "right");
            app->active_nodes[node_id-1]->conn.node_id = -1;
            app->main_node->left_conn.node_id = -1;
            app->message = "gate node disconnected from sniffer!\n";
        }else if (app->main_node->right_conn.node_id == node_id) {
            stop_worker(app, "left");
            stop_worker(app, "right");
            app->active_nodes[node_id-1]->conn.node_id = -1;
            app->main_node->right_conn.node_id = -1;
            app->message = "gate node disconnected from sniffer!\n";
        }
        else {
            app->message = "gate node not connected to sniffer!\n";
        }
        
    }else {
        stop_worker(app, "left");
        stop_worker(app, "right");
        if(app->main_node->left_conn.node_id == node_id){
            app->active_nodes[node_id-1]->conn.node_id = -1;
            app->main_node->left_conn.node_id = -1;
        }
        if (app->main_node->right_conn.node_id == node_id) {
            app->active_nodes[node_id-1]->conn.node_id = -1;
            app->main_node->right_conn.node_id = -1;
        }
        free(app->active_nodes[node_id-1]);
        app->active_nodes[node_id-1] = NULL;
        app->message = "node removed\n";
    }
    getchar();
}

//dump normal node info
void node_dump(NODE* node,char* node_type){
    char temp_mac[20];
    sprintf(temp_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 
        node->node_mac[0],
        node->node_mac[1],
        node->node_mac[2],
        node->node_mac[3],
        node->node_mac[4],
        node->node_mac[5]);
    struct sockaddr_in antelope;
    char* temp_ip;
    
    antelope.sin_addr.s_addr = node->node_ip;
    temp_ip = inet_ntoa(antelope.sin_addr);
    
    printf(node_type,
        GREEN,node->node_id,NORMAL,
        temp_ip,
        temp_mac,
        GREEN,node->conn.node_id,NORMAL
    );
}

//dump sniffer node info
void sniff_node_dump(SNIFF_NODE* node){
    char temp_mac[20];
    sprintf(temp_mac,"%x:%x:%x:%x:%x:%x", 
        node->node_mac[0],
        node->node_mac[1],
        node->node_mac[2],
        node->node_mac[3],
        node->node_mac[4],
        node->node_mac[5]);
    struct sockaddr_in antelope;
    char* temp_ip;
    
    antelope.sin_addr.s_addr = node->node_ip;
    temp_ip = inet_ntoa(antelope.sin_addr);
    
    printf(MAIN_NODE_DUMP,
        GREEN,node->node_id,NORMAL,
        temp_ip,
        temp_mac,
        GREEN,node->left_conn.node_id,NORMAL,
        GREEN,node->right_conn.node_id,NORMAL
    );
}

//functions for adding command to app
void add_cmd(APP* app,int cmd_id,char* cmd_name,char* cmd_description){
    if (cmd_id > NUM_COMMANDS) {
        printf("ohhh heap buffer overflow !");
    }else {
        APP_CMD* cmd = (APP_CMD*)malloc(sizeof(APP_CMD));
        cmd->cmd_id = cmd_id;
        cmd->cmd = cmd_name;
        cmd->cmd_description = cmd_description;
        app->app_commands[cmd_id] = cmd;
    }

}

//set first sniff
void init_sniff_node(APP* app){
    app->main_node = sniff_node_init(0,app->interface->ip_addr,app->interface->mac_addr);
}

void init_gateway_node(APP* app,unsigned int ip_addr,unsigned char * mac_addr){
    app->active_nodes[0] = node_init(1,ip_addr,mac_addr);
}

//function for executing commands
void execute_cmd(APP* app,int cmd_id){

    //add node to topology
    if (app->app_commands[cmd_id]->cmd_id == 0) {
        printf("free nodes: ");
        for (int i=1; i < MAX_NODE; i++) {
            if (app->active_nodes[i] == NULL) {
                printf("%d ",i+1);
            }
        }
        int node_id;
        printf("\nchoose one node : ");scanf("%d",&node_id);getchar();
        app->active_nodes[node_id-1] = node_init(node_id, inet_addr("0.0.0.0"), app->active_nodes[0]->node_mac);

        //create a temp buffer
        char temp_input_buf[20];

        //get node ip addr
        printf("Enter node ip : ");
        fgets(temp_input_buf, 20, stdin);
        temp_input_buf[strcspn(temp_input_buf, "\n")] = 0;
        app->active_nodes[node_id-1]->node_ip = inet_addr(temp_input_buf);

        //flush buffer
        memset(temp_input_buf, 0, 20);

        //get node mac addr
        printf("Enter node mac : ");
        fgets(temp_input_buf, 20, stdin);
        temp_input_buf[strcspn(temp_input_buf, "\n")] = 0;
        memcpy(app->active_nodes[node_id-1]->node_mac, mac_parser(temp_input_buf),ETH_ALEN);

        app->message = "new node added to topology\n";
        printf("\npress Enter to continue ...");getchar();

    //connect to one node
    }else if (app->app_commands[cmd_id]->cmd_id == 1) {
        printf("Runnung nodes: \n");
        for (int i=0; i < MAX_NODE; i++) {
            if (app->active_nodes[i] != NULL) {
                printf("%d ",i+1);
            }
        }
        int target_node_id;
        printf("\nchoose one node to connect: ");scanf("%d",&target_node_id);
        if((app->main_node->left_conn.node_id == -1) && (app->main_node->right_conn.node_id == -1)){
            set_right_node(app->main_node, app->active_nodes[target_node_id-1]);
            app->message = "connected !(connect one more node to start spoofing )\n";
        }else if ((app->main_node->left_conn.node_id == -1) && (app->main_node->right_conn.node_id != -1)) {
            set_left_node(app->main_node, app->active_nodes[target_node_id-1]);
            start_worker(app, "left", 
                //right ip
                app->main_node->right_conn.node_ip,
                //sniffer mac
                app->main_node->node_mac,
                //target mac
                app->active_nodes[target_node_id-1]->node_mac,
                //target ip
                app->active_nodes[target_node_id-1]->node_ip
            );
            start_worker(app, "right", 
                //left ip
                app->main_node->left_conn.node_ip,
                //sniffer mac
                app->main_node->node_mac,
                //right mac
                app->main_node->right_conn.node_mac,
                //right ip
                app->main_node->right_conn.node_ip
            );
            app->message = "arp spoofing started !\n";
        }else if ((app->main_node->left_conn.node_id != -1) && (app->main_node->right_conn.node_id == -1)) {
            set_right_node(app->main_node, app->active_nodes[target_node_id-1]);
            start_worker(app, "right", 
                //left ip
                app->main_node->left_conn.node_ip,
                //sniffer mac
                app->main_node->node_mac,
                //target mac
                app->active_nodes[target_node_id-1]->node_mac,
                //target ip
                app->active_nodes[target_node_id-1]->node_ip
            );
            start_worker(app, "left", 
                //right ip
                app->main_node->right_conn.node_ip,
                //sniffer mac
                app->main_node->node_mac,
                //left mac
                app->main_node->left_conn.node_mac,
                //left ip
                app->main_node->left_conn.node_ip
            );
            app->message = "arp spoofing started !\n";
        }else{
            app->message = "no free port on sniffer remove one node !\n";
        }
        getchar();

    //dump nodes
    }else if (app->app_commands[cmd_id]->cmd_id == 2) {
        //nodes reserved for app
        sniff_node_dump(app->main_node);
        node_dump(app->active_nodes[0],GATE_NODE_DUMP);
        
        int j = 1;
        while(j < MAX_NODE) {
            if (app->active_nodes[j] != NULL) {
                node_dump(app->active_nodes[j],NODE_DUMP);
            }
        j++;
        }
        app->message = "App Running\n";
        printf("\npress Enter to continue ...");getchar();

    //remove one node
    }else if (app->app_commands[cmd_id]->cmd_id == 3) {
        printf("Runnung nodes: ");
        for (int i=0; i < MAX_NODE; i++) {
            if (app->active_nodes[i] != NULL) {
                printf("%d ",i+1);
            }
        }
        int node_id;
        printf("\nchoose one node : ");scanf("%d",&node_id);
        remove_node(app,node_id);
    }
    else {
        app->message = "Invalid command!";
    }
}

void start_worker(APP* app,char* selector,unsigned int spoofed_ip,unsigned char *spoofed_mac, unsigned char *target_mac_addr,unsigned int target_ip_addr){
    if(strcmp(selector, "right")){
        app->right_worker.w_data.interface_data = app->interface;
        app->right_worker.w_data.spoofed_ip = spoofed_ip;
        memcpy(app->right_worker.w_data.spoofed_mac, spoofed_mac,ETH_ALEN);
        memcpy(app->right_worker.w_data.target_mac_addr, target_mac_addr,ETH_ALEN);
        app->right_worker.w_data.target_ip_addr = target_ip_addr;

        pthread_create(&app->right_worker.thread_id, NULL, spoof_worker, &app->right_worker.w_data);
    }else {
        app->left_worker.w_data.interface_data = app->interface;
        app->left_worker.w_data.spoofed_ip = spoofed_ip;
        memcpy(app->left_worker.w_data.spoofed_mac, spoofed_mac,ETH_ALEN);
        memcpy(app->left_worker.w_data.target_mac_addr, target_mac_addr,ETH_ALEN);
        app->left_worker.w_data.target_ip_addr = target_ip_addr;

        pthread_create(&app->left_worker.thread_id, NULL, spoof_worker, &app->left_worker.w_data);
    }
}

void stop_worker(APP* app,char* selector){
    if(strcmp(selector, "right")){
        pthread_cancel(app->right_worker.thread_id);
    }else {
        pthread_cancel(app->left_worker.thread_id);
    }
    printf("thread stopped\n");
}
//written by noob0x
