#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>


using namespace std;

#pragma pack(push,1)
struct ethernet_header
{
    u_int8_t ether_dmac[6];
    u_int8_t ether_smac[6];
    u_int16_t ether_type;

};



struct arp_header
{
    u_int16_t hard_type;
    u_int16_t protocol;
    u_int8_t h_size; //hardware size
    u_int8_t p_size; //protocol size
    u_int16_t opcode;
    u_int8_t sender_MAC[6];
    u_int8_t sender_IP[4];
    u_int8_t target_MAC[6];
    u_int8_t target_IP[4];
};

struct Vector_Session{
    u_int8_t arp_sender_IP[4];
    u_int8_t arp_target_IP[4];
    u_int8_t eth_sender_mac[6];
    u_int8_t eth_target_mac[6];
};

struct ip_header
{
    u_int8_t val; //version and length
    u_int8_t dsf;
    u_int16_t total_length;
    u_int16_t identifi;
    u_int16_t flags;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check_sum;
    u_int8_t ip_srcaddr[4];
    u_int8_t ip_destaddr[4];

};

struct tcp_header
{
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t seq_num[4];
    u_int8_t ack_num[4];
    u_int16_t flags; // header length and flags
    u_int16_t ws; //window size
    u_int16_t cs; //checksum
    u_int16_t urgent;
};


struct payload
{
    u_char http_data[10];
};

struct all_in{
    struct ethernet_header;
    struct ip_header;
    struct tcp_header;
};

#pragma pack(pop)
void usage();
u_int16_t my_ntohs(uint16_t n);
void print_ethernet(const unsigned char *data);
void print_ip(const unsigned char *data);
void print_tcp(const unsigned char *data);
void print_data(const unsigned char *data);
void ip_to_strok(char *ip,u_int8_t *array);
void print_malware_packet(const unsigned *data);
void print_arp(const unsigned char *cmp);
void get_my_mac(char *dev,u_int8_t *my_mac);
void get_my_ip(char *dev,u_int8_t *my_ip, char *errbuf);
void Set_nomal_packet(Vector_Session *data,u_int8_t *my_ip,u_int8_t *my_mac,u_char *packet,pcap_t *handle);
void set_malware_packet(Vector_Session *VS, pcap_t *handle, u_char * packet, u_int8_t *my_mac);
void Reply_packet(Vector_Session *VS,pcap_t *handle,u_char *packet, u_int8_t *my_mac,u_int8_t *sender_mac,u_int8_t *target_mac, u_int8_t *my_ip);
void get_target_mac(Vector_Session *VS,pcap_t *handle,u_char *packet, u_int8_t *my_ip,u_int8_t *my_mac);
void Send_Relay_packet(Vector_Session *VS,pcap_t *handle, u_char *packet, u_int8_t *my_mac);
