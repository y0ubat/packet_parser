#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

#pragma pack(push,1)

struct packet_eth
{
    u_int8_t daddr[6];
    u_int8_t saddr[6];
    u_int16_t type;
};

struct packet_tcp{
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_offset;  // 4 bits
  uint8_t  flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
};


struct packet_ip
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;    /* header length */
    unsigned int ip_v:4;    /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;    /* version */
    unsigned int ip_hl:4;    /* header length */
#endif
    u_int8_t ip_tos;      /* type of service */
    u_short ip_len;      /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;      /* fragment offset field */
#define  IP_RF 0x8000      /* reserved fragment flag */
#define  IP_DF 0x4000      /* dont fragment flag */
#define  IP_MF 0x2000      /* more fragments flag */
#define  IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
    u_int8_t ip_ttl;      /* time to live */
    u_int8_t ip_p;      /* protocol */
    u_short ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};




#pragma pack(pop)


int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    struct packet_tcp *tcp_;
    struct packet_eth *eth;
    struct packet_ip *ip;
    const u_char *packet;		/* The actual packet */



    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 3000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    while(1)
    {
        int res;
        int data_len;
        res = pcap_next_ex(handle, &header,&packet);

        if(!res) continue;

        printf("res : %d\n",res);
        eth = (struct packet_eth*)packet;
        packet += sizeof(struct packet_eth);
        ip = (struct packet_ip*)packet;


        printf("\n\n\n");

        printf("eht destnation: ");
        for(int i=0;i<6;++i)
            printf("%02x ",eth->daddr[i]);
        printf("\n");

        printf("eht source: ");
        for(int i=0;i<6;++i)
            printf("%02x ",eth->saddr[i]);
        printf("\n");

        switch(eth->type)
        {
        case 0x08:

            printf("dip : %s\n",inet_ntoa(ip->ip_dst));
            printf("sip : %s\n",inet_ntoa(ip->ip_src));
            \
            if(ip->ip_p == 6)
            {

                packet += sizeof(struct packet_ip);
                tcp_ = (struct packet_tcp*)packet;


                printf("dport : %d\n",ntohs(tcp_->dst_port));
                printf("sport : %d\n",ntohs(tcp_->src_port));

                packet += sizeof(struct packet_tcp);

                data_len = header.caplen - sizeof(struct packet_tcp) + sizeof(struct packet_ip) +sizeof(struct packet_eth);
                printf("data size: %d\n",data_len);

                for(int i=0;i<data_len;i++)
                        printf("%02x ",packet[i]);
                printf("\n");
            }

            break;


        }


    }


    pcap_close(handle);
    return(0);
}
