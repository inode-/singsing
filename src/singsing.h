/*****************************************************************************
 * singsing.h is a part of singsing project                                  *
 *                                                                           *
 * http://singsing.woolly-sheep.net                                          *
 *                                                                           *
 * $Id:: singsing.h 22 2007-11-21 20:51:59Z inode_                        $: *
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


#ifndef _SINGSING_H

#define _SINGSING_H

#define SINGSING_VERSION "0.4"

#define SINGSING_REVISION       "$revision$"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h> 

#ifdef SOLARIS
#include <sys/sockio.h>
#include <arpa/nameser_compat.h>
#endif

#ifdef MAC
#include <netinet/in.h>
#endif

#define SINGSING_BASIC_SCAN 	0
#define SINGSING_NODUP_SCAN	2
#define SINGSING_SEGMENT_SCAN	4
#define SINGSING_SHOW_CLOSED	8

#define SINGSING_TIMEOUT 	30

#define SINGSING_OPEN		0
#define SINGSING_CLOSE		1

struct singsing_result_queue {
	unsigned long ip;
	unsigned int port;
	unsigned char type;
	time_t rec_time;	
	struct singsing_result_queue * next;
};

struct singsing_status_struct {
	unsigned long total_port;
	unsigned long current_port;
	unsigned long synps;
	time_t init_time;
	time_t current_time;
};

struct singsing_descriptor {
	int singsing_band;
	char * singsing_device;
	unsigned long singsing_start_ip;
	unsigned long singsing_end_ip;
	unsigned int singsing_min_port;
	unsigned int singsing_max_port;
	int singsing_socket[500];
	pcap_t * singsing_descr;
	u_short singsing_ipid;
	int singsing_finished;
	unsigned int singsing_ports;
	unsigned long singsing_sleep_band;
	unsigned long singsing_synps;
	int singsing_raw_socket;
	unsigned long singsing_source_ip;
	pthread_t singsing_thread_id[3];
	unsigned long singsing_cur_port;
	unsigned int singsing_scan_mode;

	// Data lists
	struct singsing_port_list * singsing_first_port;
	struct singsing_port_list * singsing_last_port;

	struct singsing_result_queue * singsing_first_result;
	struct singsing_result_queue * singsing_last_result;
	pthread_mutex_t singsing_result_queue_lock ;

	pthread_mutex_t packet_queue_lock;

	struct singsing_packet_queue * singsing_first_packet;
	struct singsing_packet_queue * singsing_last_packet;

	struct singsing_status_struct singsing_cur_status;
};

// Prototypes
int singsing_add_port( struct singsing_descriptor * fd, unsigned int port );
int singsing_set_scan_interface( struct singsing_descriptor * fd, char * interface );
int singsing_set_scan_host( struct singsing_descriptor * fd, char * host);
int singsing_init( struct singsing_descriptor * fd );
void singsing_destroy( struct singsing_descriptor * fd );
void singsing_create( struct singsing_descriptor * fd );
int singsing_scanisfinished( struct singsing_descriptor * fd );
void singsing_set_bandwidth( struct singsing_descriptor * fd, int a);
void singsing_get_status( struct singsing_descriptor * fd, struct singsing_status_struct * cur );
void singsing_set_scanmode( struct singsing_descriptor * fd, int a );
struct singsing_result_queue * singsing_get_result( struct singsing_descriptor * fd );

#endif 

