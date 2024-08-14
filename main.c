#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
// #include <sys/socket.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#define MAX_HDR_SIZE  65536

//0. globalvar to store the diff protocols 
struct ethhdr* ethh;
struct iphdr* iph;
struct tcphdr* tcph;
struct udphdr* udph;
struct icmphdr* icmph;


//print the header
void print_ip(uint8_t* buf, int size){
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    struct sockaddr_in src, dst;
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr;
    printf("Ip header\n");
    printf(" |-Source IP: %s\n", inet_ntoa(src.sin_addr));
    printf(" |-Destination IP: %s\n", inet_ntoa(dst.sin_addr));
}

void print_tcp(uint8_t* buf, int size){
    int iphlen;
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    iphlen = iph->ihl * 4 ;
    tcph = (struct tcphdr*)(buf + iphlen + sizeof(struct ethhdr));
    printf("TCP Header\n");
    printf(" |-Source Port        : %u\n", ntohs(tcph->source));
    printf(" |-Destination Port   : %u\n", ntohs(tcph->dest));
    printf(" |-Sequence Number    : %u\n", ntohl(tcph->seq));
    printf(" |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
}


void print_udp(uint8_t* buf, int size){
    int iphlen;
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    iphlen = iph->ihl * 4 ;
    udph = (struct udphdr*)(buf + iphlen + sizeof(struct ethhdr));
    printf("UDP Header\n");
    printf(" |-Source Port      : %u\n", ntohs(udph->source));
    printf(" |-Destination Port : %u\n", ntohs(udph->dest));
    printf(" |-UDP Length       : %u\n", ntohs(udph->len));
}


void print_icmp(uint8_t* buf, int size){
    int iphlen;
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    iphlen = iph->ihl * 4 ;
    icmph = (struct icmphdr*)(buf + iphlen + sizeof(struct ethhdr));
    printf("ICMP Header\n");
    printf(" |-Type     : %u\n", icmph->type);
    if(icmph->type == 11) 
    printf("  (TTL Expired)\n");
    else if(icmph->type == 0) 
        printf("  (ICMP Echo Reply)\n");
    else if(icmph->type == 8)
        printf("  (ICMP Echo Request)\n");

    printf(" |-Code     : %u\n", icmph->code);
    printf(" |-Checksum : %u\n", ntohs(icmph->checksum));

}


//1. processing the packets
void process(uint8_t* buf, int size){
    ethh = (struct ethhdr*)buf; 
    iph = (struct iphdr*)(buf + sizeof(ethh));

    switch (iph->protocol){
    case 1:
        //ICMP
        print_icmp(buf,size);
        break;
    case 6 :
        //TCP
        print_ip(buf,size);
        print_tcp(buf,size);
        break;
    case 17 : 
        //UDP
        print_ip(buf,size);
        print_udp(buf,size);
        break;
    default:  //other
        printf("other packet\n");
        uint8_t protocol = iph->protocol;
        printf("Protocol: %d\n", protocol);
        break;
    }
      
} 

int analyze(){
    int sock_r, srcaddr_size;
    struct sockaddr srcaddr;
    uint8_t * buf = (uint8_t *) malloc(MAX_HDR_SIZE);

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_r < 0){
        perror("socket failed");
        return -1;
    }

    //loop to analize the traffic
    while(1){
        srcaddr_size = sizeof(srcaddr);
        int bytes_received = recvfrom(sock_r, buf, MAX_HDR_SIZE, 0, &srcaddr, (socklen_t*)&srcaddr_size);
        if(bytes_received < 0){
            perror("recvfrom failed");
            free(buf);
            return -1;
        }
        process(buf,bytes_received);
    }
    close(sock_r);
    free(buf);
}


int main(int argc, char const *argv[]){
    printf("starting analizing ..\n");
    analyze();
    return 0;
}
