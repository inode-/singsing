/*****************************************************************************
 * filippo.c is a part of singsing project                                   *
 *                                                                           *
 * http://singsing.sourceforge.net                                           *
 *                                                                           *
 * $Id::                                                                  $: *
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


#include "singsing.h"

#define NAME "socks"
#define VERSION "0.1"

#define PORT	23
#define READ_TIMEOUT	15
#define CONNECT_TIMEOUT 20

void usage( char * argv );
int telnet_scan(char * host, unsigned int port); 


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

	while((opt = getopt(argc, argv, "i:h:b:c:")) != -1)
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

	if( target == NULL || device == NULL )
		usage( argv[0] );

	singsing_set_scan_interface( device );

	singsing_set_bandwidth( band );

	singsing_set_scan_host( target );

	singsing_add_port( PORT );

        singsing_set_scanmode( SINGSING_NODUP_SCAN );

        singsing_set_scanmode( SINGSING_SEGMENT_SCAN );

	fprintf( stderr, "Starting scan...\n");

	start_time = time(NULL);

	singsing_init();

	do {
		cur_res = singsing_get_result();
		if( cur_res != NULL ) {
			result.s_addr = ntohl(cur_res->ip);
			//fprintf(stderr, " port opened on %s\n",inet_ntoa( result ) );
			//if( socks_v4_scan(strdup(inet_ntoa( result )), port) == 0 )
			//socks_v4_scan(strdup(inet_ntoa( result )), port);
			//	socks_v5_scan(strdup(inet_ntoa( result )), port);
			telnet_scan( strdup(inet_ntoa( result )), PORT);
			//fprintf(stderr, " end %s\n", inet_ntoa( result ));
			
			fflush(stderr);
			fflush(stdout);
			
			free(cur_res);
		} else
                	usleep(300000);
 
	} while( singsing_scanisfinished() != 2 || cur_res != NULL);


        end_time = time(NULL);

        fprintf( stderr, "\n Scan end in %.0lf seconds\n\n", difftime(end_time, start_time));

        singsing_destroy();

	return 0;
}


void usage( char * argv )
{
	fprintf(stderr, "\n Usage: %s -i <arg> -h <arg> -c <arg> [-b <arg> -p <arg>]\n", argv);
	fprintf(stderr, "\t-i Interface\n");
	fprintf(stderr, "\t-h Target (CIDR format)\n");
	fprintf(stderr, "\t-b Bandwidth (Default 5KB/s)\n");
	fprintf(stderr, "\t-p Port (Default 1080)\n");
	fprintf(stderr, "\t-c Try connect to (ip:port)\n");
	exit(0);
} 

int net_connect( char * host, int port)
{
	int sd;
	struct sockaddr_in servAddr;
	int flags, flags_old, retval, sock_len;
	struct sockaddr_in sin;
	struct timeval tv;
	fd_set rfds;

  
	//h = gethostbyname( host );
//AF_INET

	//if(h==NULL) {
//perror("pipop");
		//printf(": unknown host '%s'\n",host);
		//exit(1);
	//}

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


int telnet_scan(char * host, unsigned int port)
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

	// Testing V4 protocol
/*    * field 1: SOCKS version number, 1 byte, must be 0x04 for this version
    * field 2: command code, 1 byte:
          o 0x01 = establish a TCP/IP stream connection
          o 0x02 = establish a TCP/IP port binding
    * field 3: network byte order port number, 2 bytes
    * field 4: network byte order IP address, 4 bytes
    * field 5: the user ID string, variable length, terminated with a null (0x00)*/
	/*0x04 | 0x01 | 0x00 0x50 | 0x42 0x66 0x07 0x63 | 0x46 0x72 0x65 0x64 0x00*/

	// Trying to connect to google (209.85.135.99)


	write(sock,"\r\n\r\n\r\n",6);

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

		if( l >= 30) 
			break;
			
		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > READ_TIMEOUT) {
			close( sock );
			return 0;
		}

		
			
		usleep(3000);
		p += i;
	}

	fprintf(stdout, "***** %s *****\n%s\n", host,buff);
	fflush( stdout);

	close(sock);
	return 0;
} 
