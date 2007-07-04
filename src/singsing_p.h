/*****************************************************************************
 * singsing_p.h is a part of singsing project                                *
 *                                                                           *
 * http://singsing.sourceforge.net                                           *
 *                                                                           *
 * $Id$                                                                      *
 *                                                                           *
 * Copyright (c) 2007, Agazzini Maurizio - inode@wayreth.eu.org              *
 * All rights reserved.                                                      *
 *                                                                           *
 * Redistribution and use in source and binary forms, with or without        *
 * modification, are permitted provided that the following conditions        *
 * are met:                                                                  *
 *     * Redistributions of source code must retain the above copyright      *
 *       notice, this list of conditions and the following disclaimer.       *
 *     * Redistributions in binary form must reproduce the above copyright   *
 *       notice, this list of conditions and the following disclaimer in     *
 *       the documentation and/or other materials provided with the          *
 *       distribution.                                                       *
 *     * Neither the name of Agazzini Maurizio nor the names of its          *
 *       contributors may be used to endorse or promote products derived     *
 *       from this software without specific prior written permission.       *
 *                                                                           *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,     *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED  *
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    *
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      *
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        *
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              *
 *****************************************************************************/


#ifndef _SINGSING_P_H

#define _SINGSING_P_H

//#define DEBUG 1
// Prototypes
int singsing_checksum(unsigned short* data, int length);
unsigned short singsing_in_cksum_tcp(int src, int dst, \
	unsigned short *addr, int len);
void singsing_packet_rec(u_char *args,const struct pcap_pkthdr* pkthdr, \
	const u_char* packet);
void * singsing_processing_thread(void *parm);
void * singsing_send_syn_thread(void *parm);
int singsing_send_syn( int sock, long dest_ip , long source_ip, long port);
void * singsing_sniff_thread(void *parm);
void singsing_set_thread_priority( int priority );
unsigned long singsing_get_ip(char* interface) ;
int singsing_bind_port( unsigned long ip );


struct singsing_status_struct singsing_cur_status;

struct singsing_port_list {
	long port;
	struct singsing_port_list * next;	
};

struct singsing_packet_queue {
	const u_char* packet;
	bpf_u_int32 len;
	struct singsing_packet_queue * next;
};


// Global variables
int singsing_band = 5;
char * singsing_device	= NULL;
unsigned long singsing_start_ip = 0;
unsigned long singsing_end_ip = 0;
unsigned int singsing_min_port = 0;
unsigned int singsing_max_port = 0;
int singsing_socket[500];
pcap_t * singsing_descr	= NULL;
u_short singsing_ipid	= 0;
int singsing_finished 	= 0;
unsigned int singsing_ports = 0;
unsigned long singsing_sleep_band = 0;
unsigned long singsing_synps;
int singsing_raw_socket;
unsigned long singsing_source_ip;
pthread_t singsing_thread_id[3];
unsigned long singsing_cur_port = 0;
int singsing_scan_mode = SINGSING_BASIC_SCAN;


// Data lists
struct singsing_port_list * singsing_first_port = NULL;
struct singsing_port_list * singsing_last_port = NULL;

struct singsing_result_queue * singsing_first_result = NULL;
struct singsing_result_queue * singsing_last_result = NULL;
pthread_mutex_t singsing_result_queue_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t packet_queue_lock = PTHREAD_MUTEX_INITIALIZER;

struct singsing_packet_queue * singsing_first_packet = NULL;
struct singsing_packet_queue * singsing_last_packet = NULL;

// Fixing solaris
#ifdef SOLARIS
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#endif

/* TCP Header structure, taken from linux includes */

struct tcphdr
  {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
#  if BYTE_ORDER == LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#  endif
#  if BYTE_ORDER == BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */

    //MSS FIX!
    u_int32_t mss;
};

/* IP Header structure, taken from linux includes */

struct ip
  {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;               /* header length */
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };

#define ETH_ALEN       6               /* Octets in one ethernet addr   */
#define  ETHERTYPE_IP            0x0800          /* IP */

/* 10Mb/s ethernet header */
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t ether_type;                 /* packet type ID field */
};


struct singsing_psd_tcp {
        struct in_addr src;
        struct in_addr dst;
        unsigned char pad;
        unsigned char proto;
        unsigned short tcp_len;
        struct tcphdr tcp;
};

#endif 

