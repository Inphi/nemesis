/*
 * $Id: nemesis-proto_udp.c,v 1.1.1.1 2003/10/31 21:29:37 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 1999, 2000, 2001 Mark Grimes <mark@stateful.net>
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-proto_udp.c (UDP Packet Generator)
 *
 */

#include "nemesis-udp.h"
#include "nemesis.h"

int buildudp(ETHERhdr *eth, IPhdr *ip, UDPhdr *udp, FileData *pd, 
        FileData *ipod, char *device)
{
    int n;
    u_int32_t udp_packetlen = 0, udp_meta_packetlen = 0;
    static u_int8_t *pkt;
    static int sockfd = -1;
    struct libnet_link_int *l2 = NULL;
    u_int8_t link_offset = 0;
#if !defined(WIN32)
    int sockbuff = IP_MAXPACKET;
#endif

    if (pd->file_mem == NULL)
        pd->file_s = 0;
    if (ipod->file_mem == NULL)
        ipod->file_s = 0;

    if (got_link)   /* data link layer transport */
    {
        if ((l2 = libnet_open_link_interface(device, errbuf)) == NULL)
        {
            nemesis_device_failure(INJECTION_LINK, (const char *)device);
            return -1;
        }
        link_offset = LIBNET_ETH_H;
    }
    else
    {
        if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            nemesis_device_failure(INJECTION_RAW, (const char *)NULL);
            return -1;
        }
#if !defined(WIN32)
        if ((setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&sockbuff, 
                sizeof(sockbuff))) < 0)
        {
            fprintf(stderr, "ERROR: setsockopt() failed.\n");
            return -1;
        }
#endif
    }

    udp_packetlen = link_offset + LIBNET_IP_H + LIBNET_UDP_H + pd->file_s + 
            ipod->file_s;

    udp_meta_packetlen = udp_packetlen - (link_offset + LIBNET_IP_H);

#ifdef DEBUG
    printf("DEBUG: UDP packet length %u.\n", udp_packetlen);
    printf("DEBUG:  IP options size  %u.\n", ipod->file_s);
    printf("DEBUG: UDP payload size  %u.\n", pd->file_s);
#endif

    if (libnet_init_packet(udp_packetlen, &pkt) == -1)
    {
        fprintf(stderr, "ERROR: Unable to allocate packet memory.\n");
        return -1;
    }

    if (got_link)
        libnet_build_ethernet(eth->ether_dhost, eth->ether_shost, ETHERTYPE_IP,
                NULL, 0, pkt);

    libnet_build_ip(udp_meta_packetlen, ip->ip_tos, ip->ip_id, ip->ip_off, 
            ip->ip_ttl, ip->ip_p, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
            NULL, 0, pkt + link_offset);

    libnet_build_udp(udp->uh_sport, udp->uh_dport, pd->file_mem, 
            pd->file_s, pkt + link_offset + LIBNET_IP_H);

    if (got_ipoptions)
    {
        if ((libnet_insert_ipo((struct ipoption *)ipod->file_mem, 
                ipod->file_s, pkt + link_offset)) == -1)
        {
            fprintf(stderr, "ERROR: Unable to add IP options, discarding "
                    "them.\n");
        }
    }

    if (got_link)
        libnet_do_checksum(pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H + 
                ipod->file_s);

    libnet_do_checksum(pkt + link_offset, IPPROTO_UDP, LIBNET_UDP_H + 
            pd->file_s + ipod->file_s);

    if (got_link)
        n = libnet_write_link_layer(l2, device, pkt, udp_packetlen);
    else
        n = libnet_write_ip(sockfd, pkt, udp_packetlen);

    if (verbose == 2)
        nemesis_hexdump(pkt, udp_packetlen, HEX_ASCII_DECODE);
    if (verbose == 3)
        nemesis_hexdump(pkt, udp_packetlen, HEX_RAW_DECODE);

    if (n != udp_packetlen)
    {
        fprintf(stderr, "ERROR: Incomplete packet injection.  Only wrote "
                "%d bytes.\n", n);
    }
    else
    {
        if (verbose)
        {
            if (got_link)
                printf("Wrote %d byte UDP packet through linktype %s.\n", n, 
                        nemesis_lookup_linktype(l2->linktype));
            else
                printf("Wrote %d byte UDP packet.\n", n);
        }
    }
    libnet_destroy_packet(&pkt);
    if (got_link)
        libnet_close_link_interface(l2);
    else
        libnet_close_raw_sock(sockfd);
    return n;
}
