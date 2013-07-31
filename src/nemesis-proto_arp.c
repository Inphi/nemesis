/*
 * $Id: nemesis-proto_arp.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 *
 * nemesis-proto_arp.c (ARP Packet Generator)
 *
 */

#include "nemesis-arp.h"
#include "nemesis.h"

int buildarp(ETHERhdr *eth, ARPhdr *arp, FileData *pd, char *device,  
        int reply, ProtocolAddr *pa )
{
    int n = 0;
    u_int32_t arp_packetlen;
    static u_int8_t *pkt;
	libnet_t *l;
	libnet_ptag_t t;
	char errbuf[LIBNET_ERRBUF_SIZE];

    /* validation tests */
    if (pd->file_mem == NULL)
        pd->file_s = 0;

    arp_packetlen = LIBNET_ARP_H + LIBNET_ETH_H + pd->file_s; 

#ifdef DEBUG
    printf("DEBUG: ARP packet length %u.\n", arp_packetlen);
    printf("DEBUG: ARP payload size  %u.\n", pd->file_s);
#endif

#if 0
    if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL)
    {
        nemesis_device_failure(INJECTION_LINK, (const char *)device);
        return -1;
    }
#endif

	l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
	if (l == NULL)
	{
		fprintf(stderr, "ERROR: Libnet context uninitialized");
		return -1;
	}

	t = libnet_build_arp(arp->ar_hrd, arp->ar_pro, arp->ar_hln, arp->ar_pln, 
            arp->ar_op, pa->ar_sha, pa->ar_spa, pa->ar_tha, pa->ar_tpa,
            pd->file_mem, pd->file_s, l, 0);
	if (t == -1) 
	{
		fprintf(stderr, "ERROR: Can't build ARP header: %s\n", libnet_geterror(l));
		return -1;
	}


    t = libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, eth->ether_type,
            NULL, 0, l, 0);
	if (t == -1)
	{
		fprintf(stderr, "ERROR: Can't build ethernet header: %s\n", libnet_geterror(l));
		return -1;
	}

	if (libnet_adv_cull_packet(l, &pkt, &arp_packetlen) == -1) 
	{
		fprintf(stderr, "ERROR: %s", libnet_geterror(l));
	}
	else
	{
		if (verbose == 2)
			nemesis_hexdump(pkt, arp_packetlen, HEX_ASCII_DECODE);
		if (verbose == 3)
			nemesis_hexdump(pkt, arp_packetlen, HEX_RAW_DECODE);
	}

	n = libnet_write(l);
	if (n == -1)
	{
		fprintf(stderr, "ERROR: write: %s\n", libnet_geterror(l));
		return -1;
	}

        if (n != arp_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only "
                "wrote %d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (memcmp(eth->ether_dhost, (void *)&one, 6))
            {
                printf("Wrote %d byte unicast ARP request packet through "
                        "linktype %s.\n", n, 
                        nemesis_lookup_linktype(l->link_type));
            } 
            else
            { 
                printf("Wrote %d byte %s packet through linktype %s.\n", n, 
                        (eth->ether_type == ETHERTYPE_ARP ? "ARP" : "RARP"),
                        nemesis_lookup_linktype(l->link_type));
            }
        }
    }

	if (l != NULL)
		libnet_destroy(l);
    return (n);
}
