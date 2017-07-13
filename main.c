#include <pcap.h>
#include <stdio.h>

#pragma pack(push,1)

struct packet_eth
{
    u_int8_t daddr[6];
    u_int8_t saddr[6];
    u_int16_t type;
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
    const u_char *packet;		/* The actual packet */
    struct packet_eth *eth;

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
        pcap_next_ex(handle, &header,&packet);
        eth = (struct ether_header*)packet;
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
                printf("aaaa\n");
                break;

        }

    }
    pcap_close(handle);
    return(0);
}
