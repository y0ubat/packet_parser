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
    unsigned int ip_hl:4;    /* header length */
    unsigned int ip_v:4;    /* version */
    u_int8_t ip_tos;      /* type of service */
    u_short ip_len;      /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;      /* fragment offset field */
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
    char buf[20];
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    struct packet_tcp *tcp_;
    struct packet_eth *eth;
    struct packet_ip *ip;
    const u_char *packet;		/* The actual packet */
    int data_len = 0;


    if(!argv[1])
      printf("Using ./program network_interface\n");

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 3000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply thre filter */


    /* Grab a packet */
    while(1)
    {
        int res;
        res = pcap_next_ex(handle, &header,&packet);

        if(!res) continue;

        eth = (struct packet_eth*)packet;
        packet += sizeof(struct packet_eth);
        ip = (struct packet_ip*)packet;


        switch(eth->type)
        {
        case 0x08:


            if(ip->ip_p == 6)
            {
                data_len = ntohs(ip->ip_len)*4 - sizeof(struct packet_tcp) - sizeof(struct packet_ip);

                packet += sizeof(struct packet_ip);
                tcp_ = (struct packet_tcp*)packet;


                if(ntohs(tcp_->dst_port == 80 || ntohs(tcp_->src_port) == 80))
                {
                    packet += sizeof(struct packet_tcp);

                    printf("eht destination: ");
                    for(int i=0;i<6;++i)
                        printf("%02x ",eth->daddr[i]);
                    printf("\n");

                    printf("eht source: ");
                    for(int i=0;i<6;++i)
                        printf("%02x ",eth->saddr[i]);
                    printf("\n");

                    inet_ntop(AF_INET,&ip->ip_dst,buf,sizeof(buf));
                    printf("dip : %s\n",buf);
                    inet_ntop(AF_INET,&ip->ip_src,buf,sizeof(buf));
                    printf("sip : %s\n",buf);


                    printf("dport : %d\n",ntohs(tcp_->dst_port));
                    printf("sport : %d\n",ntohs(tcp_->src_port));
                    printf("data_len : %d\n",data_len);
                    for(int i=0;i<data_len;i++)
                        printf("%c",packet[i]);
                    printf("\n");



                }else{

                }

            }
            break;
        }
        printf("\n\n\n");
    }
    pcap_close(handle);
    return(0);
}

