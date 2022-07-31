#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

void print_eth(etherp_s ethr)
{
    printf("\n------------------------------------------------------ETHERNET HEADER------------------------------------------------------\n");
    printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", ethr->h_source[0], ethr->h_source[1], ethr->h_source[2], ethr->h_source[3], ethr->h_source[4], ethr->h_source[5]); // at least 2 numbers in hex base printing the src mac address
    printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", ethr->h_dest[0], ethr->h_dest[1], ethr->h_dest[2], ethr->h_dest[3], ethr->h_dest[4], ethr->h_dest[5]);
    printf("\t|-Protocol : %d\n", ethr->h_proto);
}

void print_iph(ipp_s iph)
{
    struct sockaddr_in source, dest;
    printf("IP header\n");
    printf("\t\t\t |- Version : %d\n", (unsigned int)iph->version);
    printf("\t\t\t |- Inter Header Length : %d DWORDS or %d BYTES\n", (unsigned int)iph->ihl, (unsigned int)iph->ihl * 4);
    printf("\t\t\t |- Type Of Service : %d\n", (unsigned char)iph->tos);
    printf("\t\t\t |- Total Length : %d Bytes\n", (unsigned short)ntohs(iph->tot_len));
    printf("\t\t\t |- Identification : %d\n", (unsigned short)iph->id);
    printf("\t\t\t |- Time To Live : %d\n", (unsigned char)iph->ttl);
    printf("\t\t\t |- Protocol : %d\n", (unsigned char)iph->protocol);
    printf("\t\t\t |- Header Checksum : %d\n", (unsigned short)ntohs(iph->check));
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    printf("\t\t\t |- Source IP : %s\n", inet_ntoa(source.sin_addr));
    printf("\t\t\t |- Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp(tcpp_s tcph)
{
    printf("\ntcp header\n");
    printf("\t\t\t |- Source Port\t : %d\n", (unsigned short)ntohs(tcph->source));
    printf("\t\t\t |- Destination Port\t : %d\n", (unsigned short)ntohs(tcph->dest));
    printf("\t\t\t |- Sequence Number\t : %d\n", (unsigned int)ntohs(tcph->seq));
    printf("\t\t\t |- Acknowledge Number\t : %d\n", (unsigned int)ntohs(tcph->ack_seq));
    printf("\t\t\t |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
    printf("\n------------------------------------------------------flags------------------------------------------------------\n");
    printf("\t\t\t\t |-Urgent flag : %d\n", (unsigned int)tcph->urg);
    printf("\t\t\t\t |-Acknowledgement flag : %d\n", (unsigned int)tcph->ack);
    printf("\t\t\t\t |-push flag : %d\n", (unsigned int)tcph->psh);
    printf("\t\t\t\t |-Reset flag : %d\n", (unsigned int)tcph->rst);
    printf("\t\t\t\t |-Synchronise flag : %d\n", (unsigned int)tcph->syn);
    printf("\t\t\t\t |-Finish flag : %d\n", (unsigned int)tcph->fin);
    printf("\t\t\t |-Window size  :%d\n", (unsigned short)ntohs(tcph->window));
    printf("\t\t\t |- checksum  :%d\n", (unsigned short)ntohs(tcph->check));
    printf("\t\t\t |- Urgent pointer  :%d\n", (unsigned short)ntohs(tcph->urg_ptr));
}
void print_udp(udpp_s udph)
{
    printf("\nUDP Header\n");
    printf("\t|-Source Port : %d\n", ntohs(udph->uh_sport));      // print soucre port in host form
    printf("\t|-Destination Port : %d\n", ntohs(udph->uh_dport)); // print destination port in host form
    printf("\t|-UDP Length : %d\n", ntohs(udph->uh_ulen));        // print length of packet without ip+eth size in host form
    printf("\t|-UDP Checksum : %d\n", ntohs(udph->uh_sum));       // print checksum in host form
}
void print_icmp(icmpp_s icmph)
{
    printf("\nICMP Header\n");
    printf("\t|-Type : %d\n", icmph->type);
    printf("\t|-Code : %d\n", icmph->code);
    printf("\t|-Checksum : %d\n", ntohs(icmph->checksum)); // print checksum in host form
    printf("\t|-Data : %d\n", (unsigned)icmph->content);
}
// get the ethetnet header - no offset needed
inline void get_eth(char *buffer, etherp_s to_fill)
{
    *to_fill = *(etherp_s)buffer;
}

// get the ip header by offseting sizeof ethernet header from the buffer
inline void get_ip(char *buffer, ipp_s to_fill)
{
    *to_fill = *(ipp_s)(buffer + sizeof(ether_s));
}
inline void get_tcp(char *buffer, int offset, tcpp_s to_fill)
{
    *to_fill = *(tcpp_s)(buffer + offset);
}
inline void get_udp(char *buffer, int offset, udpp_s to_fill)
{
    *to_fill = *(udpp_s)(buffer + offset);
}
inline void get_icmp(char *buffer, int offset, icmpp_s to_fill)
{
    *to_fill = *(icmpp_s)(buffer + offset);
}
// process and print all there is to process and print -
//  ether
//  ip
//  protocol :
//       tcp/
//       udp/
//       icmp/
//  data
static Status process_recv(char *buffer)
{
    char *remain;

    int protocol;
    int protocol_offset;

    ether_s etherh;
    ip_s iph;

    // it is unkown which protocol is used, so i declared all at once
    tcp_s tcph;
    udp_s udph;
    icmp_s icmph;

    get_eth(buffer, &etherh);
    get_ip(buffer, &iph);

    print_eth(&etherh);
    printf("check\n");

    protocol = iph.protocol;
    if (ntohs(etherh.h_proto) == ipv4)
    {
        protocol_offset = sizeof(ether_s) + (iph.ihl * 4);

        print_iph(&iph);
        switch (iph.protocol)
        {
        case tcp:
            get_tcp(buffer, protocol_offset, &tcph);
            print_tcp(&tcph);
            remain = buffer + sizeof(ether_s) + iph.ihl * 4 + tcph.doff * 4;
            while (*remain)
            {
                printf("%.2x\t", *remain);
                remain++;
            }
            break;
        case udp:
            get_udp(buffer, protocol_offset, &udph);
            print_udp(&udph);
            remain = buffer + sizeof(ether_s) + iph.ihl * 4 + sizeof(udp_s);

            while (*remain)
            {
                printf("%.2x\t", *remain);
                remain++;
            }
            break;
        case icmp:
            get_icmp(buffer, protocol_offset, &icmph);
            print_icmp(&icmph);
            remain = buffer + sizeof(ether_s) + iph.ihl * 4 + sizeof(icmp_s);
            while (*remain)
            {
                printf("%.2x\t", *remain);
                remain++;
            }
            break;
        
        }
    }
    return success;
}
// initiate the sniffing, return -1 on error
static int sniff_packets(int sock, char *buffer)
{
    Status status = success;
    int size = recvfrom(sock, buffer, max_packet_len, 0, NULL, NULL);
    printf("caught %d bytes\n", size);
    if (size <= 0)
    {
        perror("recvfrom error or 0 size\n");
        status = error;
    }
    else
    {
        status = process_recv(buffer);
    }
    return status;
}
// provide a buffer and initiate the socket
static void init(char *buffer)
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock <= 0)
    {
        perror("socket");
    }
    else
    {
        printf("succesfuly initated socket %d\nSniffing.....\n\n", sock);
        while (sniff_packets(sock, buffer))
            ;

        printf("done sniffing");
    }
    printf("closing...\n");
    close(sock);
}
int main()
{
    char *buffer = malloc(max_packet_len);
    init(buffer);

    free(buffer);
    return 1;
}
