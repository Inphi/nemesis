/*
 * $Id: nemesis.h,v 1.2 2004/05/12 23:21:38 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2001 - 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis.h
 *
 */

#ifndef __NEMESIS_H__
#define __NEMESIS_H__

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <libnet.h>

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define STPUTC(c) putchar(c);
#define STPUTS(s) { const char *p; p = s; while(*p) STPUTC(*(p++)); }

#define ARPBUFFSIZE 1472

#define DNSTCP_RAWBUFFSIZE 65403    /* plan for IP and TCP options */
#define DNSTCP_LINKBUFFSIZE 1368    /* link-layer version of above */
#define DNSUDP_RAWBUFFSIZE 65455    /* plan for IP options */
#define DNSUDP_LINKBUFFSIZE 1420    /* link-layer version of above */

#define ETHERBUFFSIZE 1500          /* max frame size */

#define ICMP_RAWBUFFSIZE 65399      /* plan for IP options & max ICMP header 
                                       len */
#define ICMP_LINKBUFFSIZE 1364      /* link-layer version of above */

#define IGMP_RAWBUFFSIZE 65467      /* plan for IP options */
#define IGMP_LINKBUFFSIZE 1432      /* link-layer version of above */

#define IP_RAWBUFFSIZE 65475        /* plan for IP options */
#define IP_LINKBUFFSIZE 1440        /* link-layer version of above */

#define RIP_RAWBUFFSIZE 65451       /* plan for IP options & max RIP header 
                                       len */
#define RIP_LINKBUFFSIZE 1416       /* link-layer version of above */

#define TCP_RAWBUFFSIZE 65415       /* plan for IP and TCP options */
#define TCP_LINKBUFFSIZE 1380       /* link-layer version of above */

#define UDP_RAWBUFFSIZE 65467       /* plan for IP options */
#define UDP_LINKBUFFSIZE 1432       /* link-layer version of above */

#define BUILD 26                /* build number, update for each build */
#define FP_MAX_ARGS 4           /* number of IP fragment parsing tokens */
#define ERRBUFFSIZE 256
#define TITLEBUFFSIZE 81
#define WINERRBUFFSIZE 1024

#define HEX_ASCII_DECODE 0x02
#define HEX_RAW_DECODE 0x04

#define INJECTION_RAW 0x02
#define INJECTION_LINK 0x04

#define PAYLOADMODE 0
#define OPTIONSMODE 1
#define OPTIONSBUFFSIZE 40

typedef struct libnet_arp_hdr ARPhdr;
typedef struct libnet_as_lsa_hdr ASLSAhdr;
typedef struct libnet_auth_hdr AUTHhdr;
typedef struct libnet_dbd_hdr DBDhdr;
typedef struct libnet_dns_hdr DNShdr;
typedef struct libnet_ethernet_hdr ETHERhdr;
typedef struct libnet_icmp_hdr ICMPhdr;
typedef struct libnet_igmp_hdr IGMPhdr;
typedef struct libnet_ip_hdr IPhdr;
typedef struct libnet_lsa_hdr LSAhdr;
typedef struct libnet_lsr_hdr LSRhdr;
typedef struct libnet_lsu_hdr LSUhdr;
typedef struct libnet_ospf_hdr OSPFhdr;
typedef struct libnet_ospf_hello_hdr OSPFHELLOhdr;
typedef struct libnet_net_lsa_hdr NETLSAhdr;
typedef struct libnet_rip_hdr RIPhdr;
typedef struct libnet_rtr_lsa_hdr RTRLSAhdr;
typedef struct libnet_sum_lsa_hdr SUMLSAhdr;
typedef struct libnet_tcp_hdr TCPhdr;
typedef struct libnet_udp_hdr UDPhdr;
typedef struct libnet_vrrp_hdr VRRPhdr;

extern char zero[ETHER_ADDR_LEN];
extern char one[ETHER_ADDR_LEN];
extern char title[TITLEBUFFSIZE];
extern char errbuf[ERRBUFFSIZE];
extern char *pcap_outfile;
extern char *validtcpflags;
extern const char *version;
extern int verbose;
extern int got_link;
extern int got_ipoptions;
extern int got_tcpoptions;

typedef struct _ProtocolAddr
{
	u_char ar_sha[6]; 
	u_char ar_spa[4];
	u_char ar_tha[6];
	u_char ar_tpa[4];
} ProtocolAddr;

typedef struct _FileData
{
    int32_t file_s;         /* file size */
    u_int8_t *file_mem;     /* pointer to file memory */
} FileData;

/* support functions */
u_int32_t xgetint32(const char *);
u_int16_t xgetint16(const char *);
u_int8_t xgetint8(const char *);
//int gmt2local(time_t);
int nemesis_name_resolve(char *, u_int32_t *);
int nemesis_check_link(ETHERhdr *, char *);
int nemesis_getdev(int, char **);
char *nemesis_lookup_linktype(int);
int nemesis_seedrand(void);
int parsefragoptions(IPhdr *, char *);

#if defined(WIN32) || !defined(HAVE_INET_ATON)
    int inet_aton(const char *, struct in_addr *);
#endif
#if defined(WIN32) || !defined(HAVE_GETOPT)
    int getopt(int, char * const *argv, const char *);
#endif
#if defined(WIN32) || !defined(HAVE_STRLCAT)
        size_t strlcat(char *, const char *, size_t);
#endif
#if defined(WIN32) || !defined(HAVE_STRLCPY)
	    size_t strlcpy(char *, const char *, size_t);
#endif
#if defined(WIN32) || !defined(HAVE_STRSEP)
    char *strsep(char **, const char *);
#endif
#if defined(WIN32)
    void PrintDeviceList(const char *);
    void *GetAdapterFromList(void *, int);
    int getdev(int, char **);
    int winstrerror(LPSTR, int);
#endif

/* file I/O functions */
int builddatafromfile(const size_t, FileData *, const char *, 
        const u_int32_t);

/* printout functions */
void nemesis_hexdump(char *, u_int32_t, int);
void nemesis_device_failure(int, const char *);
void nemesis_maketitle(char *, const char *, const char *);
void nemesis_printeth(ETHERhdr *);
void nemesis_printarp(ARPhdr *);
void nemesis_printip(IPhdr *);
void nemesis_printtcp(TCPhdr *);
void nemesis_printudp(UDPhdr *);
void nemesis_printicmp(ICMPhdr *, int);
void nemesis_printrip(RIPhdr *);
void nemesis_printospf(OSPFhdr *);
void nemesis_printtitle(const char *);
void nemesis_usage(char *);

/* injection functions */
void nemesis_arp(int, char **);
void nemesis_dns(int, char **);
void nemesis_ethernet(int, char **);
void nemesis_icmp(int, char **);
void nemesis_igmp(int, char **);
void nemesis_ip(int, char **);
void nemesis_ospf(int, char **);
void nemesis_rip(int, char **);
void nemesis_tcp(int, char **);
void nemesis_udp(int, char **);

#endif /* __NEMESIS_H__ */
