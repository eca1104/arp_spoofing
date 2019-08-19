#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <vector>
#include "custom.h"
#include <iostream>


using namespace std;


int main(int argc, char* argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    u_int8_t my_mac[6];
    u_int8_t my_ip[4];


    get_my_mac(dev,my_mac);
    get_my_ip(dev,my_ip,errbuf);


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }


    vector<Vector_Session*>session;
    vector<u_int8_t*>arp_pack;

    uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t unknown_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    if(argc%2==1){
        printf("[-] Warning! Check the Syntax");
        usage();
    }


       for (int i = 0; i < (argc - 1) / 2; i++){
           Vector_Session* VS = new Vector_Session;
           char * argv_sender_tmp=argv[2*i+2];
           char * argv_target_tmp=argv[2*i+3];

           u_int8_t argv_to_send[4];
           u_int8_t argv_to_target[4];

           ip_to_strok(argv_sender_tmp,argv_to_send);
           ip_to_strok(argv_target_tmp,argv_to_target);


           memcpy(VS->arp_sender_IP,argv_to_send,4);
           memcpy(VS->arp_target_IP,argv_to_target,4);
           memcpy(VS->eth_sender_mac,broadcast,6);
           memcpy(VS->eth_target_mac,unknown_mac,6);

           session.push_back(VS);
       }
//       vector<Vector_Session>::iterator iter;
//       iter=session.begin();iter!=session.end();,++iter == auto a:session

       for(auto s:session){
           u_char packet[42];
           u_int8_t sender_mac[6];
           u_int8_t target_mac[6];

           Set_nomal_packet(s,my_ip,my_mac,packet,handle);

           Reply_packet(s,handle,packet,my_mac,sender_mac,target_mac,my_ip);


           Send_Relay_packet(s,handle,packet,my_mac);
       }

       pcap_close(handle);
       return 0;


}
