#include <stdio.h>            /* Standard C include file for I/O functions */
#include <time.h>             /* Include file for time manipulation functions */
#include <linux/if_ether.h>   /* Definition of the 'ethhdr' structure */
#include <pcap.h>             /* Include files for libpcap functions */

/* Prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*
struct pcap_pkthdr {
    struct timeval ts; // timestamp
    bfp_u_int32 caplen; // captured packet length
    bfp_u_int32 len;    // total packet length
}
struct timeval {
    long tv_sec;    // seconds
    long tv_usec;    // microseconds
}
struct ether_header {
    u_int8_t ether_dhost[6];    // 6 bytes destination address
    u_int8_t ether_shost[6];    // 6 bytes source address
    u_int16_t ether_type;   // 2 bytes ethertype

}
struct ip_header {
    u_int8_t lenver; // header length + version
    u_int8_t ip_tos; // type of service 
    u_int16_t ip_len; // total length 
    u_int16_t ip_id; // identification 
    u_int16_t ip_off; // fragment offset field 
    u_int8_t ip_ttl; // time to live 
    u_int8_t ip_p; // protocol 
    u_int16_t ip_sum; // checksum 
    u_int8_t ip_src[4]; // source and dest address 
    u_int8_t ip_dst[4]; // source and dest address 
};
*/
int main(int argc, char **argv)
{
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 2)
    {	
        printf("Usage: %s network_device_name (e.g., eth0)\n\n", argv[0]);
        return -1;
    }

    /* Open the capture device */
    if ( (adhandle= pcap_open_live(argv[1],     // name of the device
                              65536,            // portion of the packet to capture
                                                // 65536 guarantees that the whole packet is captured
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout, 1 second
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter: either %s is not supported by libpcap, ", argv[1]);
        fprintf(stderr, "or you do not have 'superuser' privileges\n\n");
        return -1;
    }

    printf("\nlistening on %s...\n", argv[1]);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}


/* Callback function invoked by libpcap for each incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *tm;
    char timestr[32];
    time_t local_tv_sec;
    struct ethhdr *ethptr;

    // printf("", pkt_data);
    // printf(header);

    // we know that the first 14 bytes will give me the addressess, and the type of the following data
    /* Cast the packet buffer into a pointer to an Ethernet frame */
    ethptr = (struct ethhdr *) pkt_data;

    /* Convert the timestamp to a readable format */
    local_tv_sec = header->ts.tv_sec;
    tm= localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", tm);

    printf("%s.%.6ld len:%d - ", timestr, header->ts.tv_usec, header->len);

    if (ntohs(ethptr->h_proto) == 0x800)
        printf("IP packet\n");
    else
        printf("!IP packet\n"); 
}