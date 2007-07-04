/*****************************************************************************
 *                                                                           *
 * zucca is a port scanner based on singsing project                         *
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

#define VERSION "0.3"

// #define DEFAULT_TIMEOUT  	30
// #define DEFAULT_BANDWIDTH 	15


/* global variables */
int host_ports	= 0;
int show_closed = 0;
// long total_port = 0;
extern int errno;

/* Prototypes */
int parse_system_service( void );
void parse_port( char * ports );
void usage( char * argv0 );


int main( int argc, char ** argv )
{

	char opt;
 	char * ports = NULL;

	struct singsing_result_queue * cur_res;
	struct in_addr result;



	while((opt = getopt(argc, argv, "i:b:p:h:ct:s:")) != -1)
	{
		switch (opt)
                {
			case 'i':
				singsing_set_scan_interface( optarg );
				break;
			case 'b':
				singsing_set_bandwidth( atoi( optarg ) );
				break;
//			case 't':
// 				timeout = atoi( optarg );
// 				break;
			case 'h':
				singsing_set_scan_host( optarg );
				break;
			case 'p':
				ports = optarg;
				break;
			case 'c':
				show_closed = 1;
				fprintf(stderr, "\noption -c not implemented yet\n");
				exit( EXIT_SUCCESS );
				break;
			case 's':
// 				sleeper = atoi( optarg );
 				fprintf(stderr, "\noption -s not implemented yet\n");
				break;
			default :
				usage(argv[0]);
				break;
		}
	}

	fprintf(stderr, "\n zucca syn scanner v%s with singsing v%s\n", VERSION, SINGSING_VERSION);
        fprintf(stderr, " by inode@wayreth.eu.org\n\n");

	host_ports = 0;

	if( ports != NULL ) 
		parse_port( ports );
	else
		parse_system_service();

	fprintf(stderr, " Ports per host  : %u\n", host_ports);


	singsing_set_scanmode( SINGSING_NODUP_SCAN );

	fprintf( stderr, " Starting scan...\n\n");

	singsing_init();

        do {
                cur_res = singsing_get_result();
                if( cur_res != NULL ) {
                        result.s_addr = ntohl(cur_res->ip);
                        printf("zucca open %s:%u\n",inet_ntoa( result ), cur_res->port );

                        free(cur_res);
                } else
                        usleep(300000);

        } while( singsing_scanisfinished() != 2 || cur_res != NULL);


	singsing_destroy();	

	exit( EXIT_SUCCESS );
}


/* Parse /etc/services */
int parse_system_service( void )
{
	struct servent * tmp;

	while( ( tmp = getservent()) != NULL ) {
		if( strcmp( tmp->s_proto, "tcp") == 0 ) {

			singsing_add_port( ntohs(tmp->s_port) );

			host_ports++;
		}
	}

	endservent();

	return 0;
} 

/* Parse port command line */
void parse_port( char * ports )
{
	char * tmp;
	long port;

	if( ( tmp = strchr( ports, ',')	) != NULL ) {
		*tmp = 0;
		tmp++;

		parse_port( ports );
		parse_port( tmp );

		return; 
	}

	if( ( tmp = strchr( ports, '-') ) != NULL ) {
		char number[10];
		int i;

		*tmp = 0;
		tmp++;

		for( i = atol( ports ); i <= atol(tmp); i++) {
			snprintf( number, sizeof(number), "%d", i);
			parse_port( number );
		}
		return;
	}

        if( (port = atol(ports)) > 0 ) {
		singsing_add_port( port );
                host_ports++;

                return;
        } 
	
	return;
}

void usage( char * argv0 )
{
	fprintf( stderr, " Usage:\n");
	fprintf( stderr, "  %s -h <arg> -i <arg> [-b <arg>] [-p <arg>] [-t <arg>] [-s <arg>] [-c]\n\n",argv0);
	fprintf( stderr, " -h Host/s to scan  (ex 192.168.0.0/24)\n");
	fprintf( stderr, " -i Interface\n");
	fprintf( stderr, " -b Usable bandwidth in KB (Default 15)\n");
// 	fprintf( stderr, " -m Mode fast/accurate (Default fast)\n");
	fprintf( stderr, " -p Ports (ex 22,23,40-50,99)\n");   
// 	fprintf( stderr, " -t Timeout (Default 5)\n");
//         fprintf( stderr, " -s Sleep X second after a port\n");
// 	fprintf( stderr, " -c Display closed ports\n\n");

	exit( EXIT_FAILURE );
}
