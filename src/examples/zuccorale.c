/*****************************************************************************
 * zuccorale.c is a part of singsing project                                 *
 *                                                                           *
 * $Id::                                                                  $: *
 *                                                                           *
 * Copyright (c) 2007, Agazzini Maurizio - inode@mediaservice.net            *
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
 *     * Neither the name of @ Mediaservice.net nor the names of its         *
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


#include "singsing.h"

#define VERSION "0.1"

#define ORACLE_PORT	1521
#define READ_TIMEOUT	10
#define CONNECT_TIMEOUT 30

void usage( char * argv );
int oracle_scan(char * host, unsigned int port, char * command, int len); 
int socks_v5_scan(char * host, unsigned int port);

unsigned int port = ORACLE_PORT;

int connect_ip[4];
unsigned int target_port;
unsigned int target_port1;

// WORKING 1
char command1[]="\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03";

// WORKING 2
char command2[]="\x00\x5a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x20\x00\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\xe6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x28\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x44\x41\x54\x41\x3d\x28\x43\x4f\x4d\x4d\x41\x4e\x44\x3d\x76\x65\x72\x73\x69\x6f\x6e\x29\x29";



int main(int argc, char ** argv)
{
	char * target = NULL;
	char * device = NULL;
	char opt;
	struct in_addr result;
        time_t start_time;
        time_t end_time;
	int band = 5;

	struct singsing_result_queue * cur_res;

	struct singsing_descriptor fd;

        fprintf(stderr, "\n zuccorale v%s with singsing v%s revision %s\n", VERSION, SINGSING_VERSION, SINGSING_REVISION);


	singsing_create(&fd);

	while((opt = getopt(argc, argv, "i:h:b:")) != -1)
	{
		switch (opt)
		{
			case 'i':
				device = optarg;
				break;
			case 'h':
				target = optarg;
				break;
			case 'b':
				band = atoi( optarg );
				break;
			default:
				usage( argv[0] );
		}
	}

	if( device == NULL || target == NULL )
		usage( argv[0] );

	singsing_set_scan_interface( &fd, device );

	singsing_set_bandwidth( &fd, band );

	singsing_set_scan_host( &fd, target );

	singsing_add_port( &fd, port );


        singsing_set_scanmode( &fd, SINGSING_NODUP_SCAN );

        singsing_set_scanmode( &fd, SINGSING_SEGMENT_SCAN );

	fprintf( stderr, "\n Starting scan...\n");

	start_time = time(NULL);

	singsing_init( &fd );

	do {
		cur_res = singsing_get_result( &fd );
		if( cur_res != NULL ) {
			result.s_addr = ntohl(cur_res->ip);

			fprintf(stderr," Oracle port found on ip: %s\n",inet_ntoa( result ));

			if( oracle_scan(strdup(inet_ntoa( result )), port, command1, sizeof(command1)) < 1 )
				oracle_scan(strdup(inet_ntoa( result )), port, command2, sizeof(command2));
			
			fflush(stderr);
			fflush(stdout);
			
			free(cur_res);
		} else
                	usleep(300000);
 
	} while( singsing_scanisfinished(&fd) != 2 || cur_res != NULL);


        end_time = time(NULL);

        fprintf( stderr, "\n Scan end in %.0lf seconds\n\n", difftime(end_time, start_time));

        singsing_destroy(&fd);

	return 0;
}


void usage( char * argv )
{
	fprintf(stderr, "\n Usage: %s -i <arg> -h <arg> [-b <arg>]\n", argv);
	fprintf(stderr, "\t-i Interface\n");
	fprintf(stderr, "\t-h Target (CIDR format)\n");
	fprintf(stderr, "\t-b Bandwidth (Default 5KB/s)\n\n");
	exit(0);
} 

int net_connect( char * host, int port)
{
	int sd;
	struct sockaddr_in servAddr;
	int flags, flags_old, retval;
	unsigned int sock_len;
	struct sockaddr_in sin;
	struct timeval tv;
	fd_set rfds;

	servAddr.sin_family = AF_INET;
	//memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_addr.s_addr = inet_addr(host);
	servAddr.sin_port = htons( port );

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd<0) {
		perror("cannot open socket ");
		exit(1);
	}

	// Set Non Blocking Socket
	flags_old = fcntl( sd, F_GETFL,0);
	flags = flags_old;
	flags |= O_NONBLOCK;
	fcntl( sd, F_SETFL, flags);

	if( connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) == 0) {
		fcntl( sd, F_SETFL, flags_old);
		return sd;
	}
	
	// Set timeout
	tv.tv_sec = CONNECT_TIMEOUT;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sd, &rfds);
	
	retval = select(FD_SETSIZE, NULL, &rfds, NULL, &tv);

	// if retval < 0 error
	if( retval < 0 ) {
		close( sd );
		return -1;
	}
	sock_len = sizeof( sin );

	// Check if port closed
	if( retval ) {
		if( getpeername( sd, (struct  sockaddr  *) &sin, &sock_len) < 0 ) {
			close( sd );
			return -1;
		} else {
			// XXX
			fcntl( sd, F_SETFL, flags_old);
			return sd;
		}
	}
	close( sd );
	return -1;

} 


int oracle_scan(char * host, unsigned int port, char * command, int len)
{
	int sock, flags,i,l;
	char buff[2000];
        struct timeval tv;
	char * p;
        time_t cur_time;
        time_t start_time;


	fd_set rfds; 

	memset( buff, 0, sizeof(buff));

	p = buff;
	l = 0;

	sock = net_connect(host, port);

	if( sock < 0 )
		return 0;

	target_port1 = htons( target_port );

	write(sock,command, len );

        tv.tv_sec = READ_TIMEOUT;
        tv.tv_usec = 0;

        flags = fcntl( sock, F_GETFL,0);
        flags |= O_NONBLOCK;
        fcntl( sock, F_SETFL, flags);

	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

        start_time = time(NULL);

	while( select( FD_SETSIZE , &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		i = read( sock, buff ,sizeof( buff )); 
		l += i;

		cur_time = time(NULL);

		if( i < 0) {
			close( sock );
			return 0;
		}

		if( l >= 8) 
			break;
			
		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > READ_TIMEOUT) {
			close( sock );
			return 0;
		}

		
			
		usleep(3000);
		p += i;
	}

	if( l > 0 )
		fprintf(stderr, "  Oracle response at ip: %s read %u bytes\n", host,l);
		
	close(sock);
	return l;
} 


