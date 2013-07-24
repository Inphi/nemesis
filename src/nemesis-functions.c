/*
 * $Id: nemesis-functions.c,v 1.2 2004/10/07 01:20:56 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-functions.c (nemesis utility functions)
 *
 */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(TIME_WITH_SYS_TIME) || defined(WIN32)
    #include <sys/time.h>
    #include <time.h>
#else
    #if defined(HAVE_SYS_TIME_H)
        #include <sys/time.h>
    #elif defined(HAVE_TIME_H)
        #include <time.h>
    #endif
#endif
#if defined(WIN32)
    #include <pcap.h>
#endif
#include <unistd.h>
#if defined(HAVE_LIMITS_H) || defined(WIN32)
    #include <limits.h>
#endif
#if defined(HAVE_NETDB_H)
    #include <netdb.h>
#endif
#include <math.h>
#if defined(HAVE_ERRNO_H) || defined(WIN32)
    #include <errno.h>
#endif
#if defined(HAVE_NETINET_IN_H)
    #include <netinet/in.h>
#elif defined(WIN32)
    #include <winsock2.h>
    #include <process.h>
#endif
#include <libnet.h>
#include "nemesis.h"

const char *version = " -=- The NEMESIS Project Version 1.4";

char zero[ETHER_ADDR_LEN];
char one[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char title[TITLEBUFFSIZE];
char errbuf[ERRBUFFSIZE];   /* all-purpose error buffer */
char *validtcpflags = "FSRPAUEC-";   /* TCP flag index */
int verbose;    /* verbosity */
int got_link;
int got_ipoptions;
int got_tcpoptions;


/**
 * Convert user supplied string to a u_int32_t or exit on invalid data.
 *          
 * @param str string to be converted
 *
 * @returns u_int32_t conversion of input string
 */
u_int32_t xgetint32(const char *str)
{
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > UINT_MAX || str == endp || *endp)
    {
        fprintf(stderr, "ERROR: Argument %s must be a positive integer between "
                "0 and %u.\n", str, UINT_MAX);
        exit(1);
    }
    else
        return (u_int32_t)val;
}

/**
 * Convert user supplied string to a u_int16_t or exit on invalid data.
 *          
 * @param str string to be converted
 *
 * @return u_int16_t conversion of input string
 */
u_int16_t xgetint16(const char *str)
{
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > USHRT_MAX || str == endp || *endp)
    {
        fprintf(stderr, "ERROR: Argument %s must be a positive integer between "
                "0 and %hu.\n", str, USHRT_MAX);
        exit(1);
    }
    else
        return (u_int16_t)val;
}

/**
 * Convert user supplied string to a u_int8_t or exit on invalid data.
 *          
 * @param str string to be converted
 *
 * @return u_int8_t conversion of input string
 */
u_int8_t xgetint8(const char *str)
{
    char *endp;
    u_long val;

    val = strtoul(str, &endp, 0);
    if (val > UCHAR_MAX || str == endp || *endp)
    {
        fprintf(stderr, "ERROR: Argument %s must be a positive integer between "
                "0 and %u.\n", str, UCHAR_MAX);
        exit(1);
    }
    else
        return (u_int8_t)val;
}


/**
 * Parses a string to set the fragmentation options in an IP header
 *
 * @param iph pointer to an IPhdr structure
 * @param str string to be parsed
 *
 * @note Optimized by Marty Roesch <roesch@sourcefire.com>.
 *
 * @return 0 on sucess, -1 on failure
 **/
int parsefragoptions(IPhdr *iph, char *str)
{
    int reserved = 0, dont = 0, more = 0, offset = 0;
    int i, argcount = 0;
    u_int8_t error = 0;
    char *orig = NULL;          /* original input string */
    char *toks[FP_MAX_ARGS];    /* break all args down into option sets */
    char **ap;
    u_int16_t frag_offset = 0;

    orig = strdup(str);

    for (ap = toks; ap < &toks[FP_MAX_ARGS] && 
            (*ap = strsep(&str, " ,")) != NULL; )
    {
        if (**ap != '\0')
        {
            ap++;
            argcount++;
        }

    }
    *ap = NULL;

    for (i = 0; i < argcount; i++)
    {
        if (toks[i][0] == 'D')
        {
            if (!dont)
                dont++;
            else
            {
                error++;
                break;
            }
        }
        else if (toks[i][0] == 'M')
        {
            if (!more)
                more++;
            else
            {
                error++;
                break;
            }
        }
        else if (toks[i][0] == 'R')
        {
            if (!reserved)
                reserved++;
            else
            {
                error++;
                break;
            }
        }
        else if (isdigit((int)toks[i][0]))
        {
            if (!offset)
            {
                offset++;
                frag_offset = xgetint16(toks[i]);
            }
            else
            {
                error++;
                break;
            }
        }
        else
        {
            error++;
            break;
        }
    }
    
    if (error > 0)
    {
        fprintf(stderr, "ERROR: Invalid IP fragmentation options "
                "specification: %s.\n", orig);

        if (orig != NULL)
            free(orig);

        return -1;
    }

    if (frag_offset > 8189)
    {
        fprintf(stderr, "ERROR: Fragmentation offset %hu must be a positive "
               "integer between 0 and 8189.\n", frag_offset);

        if (orig != NULL)
            free(orig);

        return -1;
    }

    iph->ip_off = (frag_offset & IP_OFFMASK) | ((reserved == 1 ? IP_RF : 0) |
            (dont == 1 ? IP_DF : 0) | (more == 1 ? IP_MF : 0));

    if (orig != NULL)
        free(orig);

    return 0;
}


/**
 *
 * Convert a hostname or IP address, supplied in ASCII format, to an u_int32_t 
 * in network byte order.
 *
 * @param hostname host name or IP address in ASCII
 * @param address u_int32_t pointer to hold converted IP
 *
 * @return 0 on sucess, -1 on failure
 */
int nemesis_name_resolve(char *hostname, u_int32_t *address)
{
    struct in_addr saddr;
    struct hostent *hp = NULL;
#if !defined(WIN32)
    extern int h_errno;
#else
    TCHAR WinErrBuf[1000];
#endif

    if (address == NULL || hostname == NULL)
        return -1;

    if ((inet_aton(hostname, &saddr)) < 1)
    {
        if ((hp = gethostbyname(hostname)) == NULL)
        {
#if !defined(WIN32)
            fprintf(stderr, "ERROR: Unable to resolve supplied hostname: "
                    "%s. %s\n", hostname, hstrerror(h_errno));
#else
            if (winstrerror(WinErrBuf, sizeof(WinErrBuf)) < 0)
                return -1;
            else
            {
                fprintf(stderr, "ERROR: Unable to resolve supplied hostname: "
                        "%s.\n%s\n", hostname, WinErrBuf);
            }
#endif
            return -1;
        }
        /* Do not blindly disregard the size of the address returned */
        if (hp->h_length != 4)
        {
            fprintf(stderr, 
                    "ERROR: nemesis_name_resolve() received a non IPv4 "
                    "address.\n");
            return -1;
        }
        memcpy((u_int32_t *)address, hp->h_addr, 4);
        return 0;
    }
    else
    {
        if (!memcmp(&saddr.s_addr, zero, 4))
            return -1;

        memcpy((u_int32_t *)address, &saddr.s_addr, 4);
        return 0;
    }
}


/**
 * Determine if a source Ethernet address has been specified and fill in the 
 * ETHERhdr structure if necessary.
 *
 * @param eth ETHERhdr pointer containing the source Ethernet address
 * @param device char pointer containing the Ethernet device name
 *
 * @return 0 on sucess, -1 on failure
 */
int nemesis_check_link(ETHERhdr *eth, char *device)
{
    int i;
    struct ether_addr *e = NULL;
    struct libnet_link_int l2;

    memset(&l2, 0, sizeof(struct libnet_link_int));
#ifdef DEBUG
    printf("DEBUG: determining if device %s\n       has a hardware address "
            "assigned.\n", device);
#endif
    if (!memcmp(eth->ether_shost, zero, 6))
    {
        memset(&l2, 0, sizeof(l2));
        if ((e = libnet_get_hwaddr(&l2, device, errbuf)) == NULL)
            return -1;

        for (i = 0; i < 6; i++)
            eth->ether_shost[i] = e->ether_addr_octet[i];

        return 0;
    } 
    else
        return 0;
}


/**
 * Lookup and return the string associated with each link type.
 *
 * @param linktype integer represntation of linktype
 *
 * @return char * containing the appropriate linktype or Unknown on a failed
 *         match.
 */
char *nemesis_lookup_linktype(int linktype)
{
    char *dlt;

    switch(linktype)
    {
        case 0:
            dlt = "DLT_NULL";
            break;
        case 1:
            dlt = "DLT_EN10MB";
            break;
        case 2:
            dlt = "DLT_EN3MB";
            break;
        case 3:
            dlt = "DLT_AX25";
            break;
        case 4:
            dlt = "DLT_PRONET";
            break;
        case 5:
            dlt = "DLT_CHAOS";
            break;
        case 6:
            dlt = "DLT_IEEE802";
            break;
        case 7:
            dlt = "DLT_ARCNET";
            break;
        case 8:
            dlt = "DLT_SLIP";
            break;
        case 9:
            dlt = "DLT_PPP";
            break;
        case 10:
            dlt = "DLT_FDDI";
            break;
        case 11:
            dlt = "DLT_ATM_RFC1483";
            break;
        case 12:
            dlt = "DLT_LOOP";
            break;
        case 13:
            dlt = "DLT_ENC";
            break;
        case 14:
            dlt = "DLT_RAW";
            break;
        case 15:
            dlt = "DLT_SLIP_BSDOS";
            break;
        case 16:
            dlt = "DLT_PPP_BSDOS";
            break;
        default:
            dlt = "UNKNOWN";
    }
    return dlt;
}


/**
 * Seed the random number generator
 *
 * @return 0 on success, -1 on failure
 */
int nemesis_seedrand(void)
{
#if !defined(WIN32)
    extern int errno;
    struct timeval tv;

    if (gettimeofday(&tv, NULL) == -1)
    {
        fprintf(stderr, "ERROR: nemesis_seedrand() failed in gettimeofday(): "
                "%s.\n", strerror(errno));
        return -1;
    }
    srandom((unsigned int)tv.tv_usec ^ (unsigned int)fabs(fmod(time(NULL), 
            UINT_MAX)));
#endif
    return 0;
}


#if 0
/**
 * Figures out how to adjust the current clock reading based on the timezone 
 * you're in.  Ripped off from TCPdump.
 *
 * @param time_t offset from GMT
 *
 * @return offset seconds from GMT
 */
int gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);

    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);

    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + 
            (loc->tm_min - gmt->tm_min) * 60;

    dir = loc->tm_year - gmt->tm_year;

    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;

    dt += dir * 24 * 60 * 60;
    return(dt);
}
#endif

#if defined(WIN32)
/**
 * Lookup Windows system errors and copy them into a user supplied buffer.
 *
 * @param str Buffer to hold the error string.
 * @param size Size of the error buffer.
 *
 * @return void function.
 */
int winstrerror(LPSTR str, int size)
{
    LPVOID lpMsgBuf;

    if (str != NULL && size > 2)
    {
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, 
                SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);

        strlcpy(str, (LPCTSTR)lpMsgBuf, size);
        LocalFree(lpMsgBuf);
        lpMsgBuf = NULL;
        return 0;
    }
    else
    {
        fprintf(stderr, "ERROR: winstrerror() received NULL buffer or "
                "buffer length < 2.\n");
        return -1;
    }
}


/**
 *
 * Lookup the Windows device name from the list of network devices and return 
 * the proper device at the user-supplied list index.
 *
 * @param devnum Device number.
 *
 * @return 0 on sucess, -1 on failure
 */
int nemesis_getdev(int devnum, char **device)
{
    char *lookuptmp = NULL;

    if (devnum > 0)
    {
        if ((lookuptmp = pcap_lookupdev(errbuf)) == NULL)
        {
            fprintf(stderr, "ERROR: Unable to allocate device memory: %s."
                    "\n", errbuf);
            return -1;
        }
        else
        {
            device = GetAdapterFromList(lookuptmp, devnum);
            return 0;
        }
    }
    else
    {
        fprintf(stderr,"ERROR: Invalid interface: '%d'.\n", devnum);
        return -1;
    }
}
#endif /* WIN32 */
