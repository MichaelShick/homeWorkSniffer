#include <stdio.h>           //For standard things
#include <stdlib.h>          //malloc
#include <string.h>          //memset
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>     //Provides declarations for udp header
#include <netinet/tcp.h>     //Provides declarations for tcp header
#include <netinet/ip.h>      //Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
void ProcessPacket(unsigned char *buffer, int size)
{
    // Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr *)buffer;
    ++total;
    switch (iph->protocol) // Check the Protocol and do accordingly...
    {
    case 1: // ICMP Protocol
        ++icmp;
        // PrintIcmpPacket(Buffer,Size);
        break;

    case 2: // IGMP Protocol
        ++igmp;
        break;

    case 6: // TCP Protocol
        ++tcp;
        break;

    case 17: // UDP Protocol
        ++udp;
        break;

    default: // Some Other Protocol like ARP etc.
        ++others;
        break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp, udp, icmp, igmp, others, total);
}
int main()
{
    char *buffer = malloc(65536);
    struct sockaddr saddr;
    struct in_addr in;
    int sock_raw, data_size;
    int saddr_size = sizeof saddr;
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw == 0 || sock_raw == -1)
    {
        perror("error with socket");
        exit(1);
    }
    printf("ready to catch with socketd %d", sock_raw);
    while (1)
    {
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
        if (data_size == -1 || data_size <= 0)
        {
            perror("error with recv");
            exit(1);
        }
        printf("caught %d bytes\n", data_size);
        ProcessPacket(buffer,data_size);
    }
    return 1;
}