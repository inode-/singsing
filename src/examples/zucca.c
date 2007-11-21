/*****************************************************************************
 * zucca.c is a part of singsing project                                     *
 *                                                                           *
 * http://singsing.woolly-sheep.net                                          *
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

#include <term.h>

#define VERSION "0.4"

/* global variables */
int host_ports	= 0;
int show_closed = 0;

extern int errno;
struct termios savetty;


/* Prototypes */
int parse_system_service( struct singsing_descriptor * fd );
void parse_port( struct singsing_descriptor * fd, char * ports );
void usage( char * argv0 );
void tty_raw( void );
void tty_normal( void );
int getch( void );

int main( int argc, char ** argv )
{

	char opt;
 	char * ports = NULL;
	char buf[200];

	struct singsing_result_queue * cur_res;
	struct singsing_status_struct current_status;
	struct in_addr result;

	struct singsing_descriptor fd;

	time_t endtime;
	time_t cur;

	struct tm ts;

	singsing_create(&fd);

	while((opt = getopt(argc, argv, "i:b:p:h:ct:s:")) != -1)
	{
		switch (opt)
                {
			case 'i':
				singsing_set_scan_interface( &fd, optarg );
				break;
			case 'b':
				singsing_set_bandwidth( &fd, atoi( optarg ) );
				break;
			case 'h':
				singsing_set_scan_host( &fd, optarg );
				break;
			case 'p':
				ports = optarg;
				break;
			case 'c':
				singsing_set_scanmode( &fd, SINGSING_SHOW_CLOSED );
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
		parse_port( &fd, ports );
	else
		parse_system_service( &fd );

	fprintf(stderr, " Ports per host  : %u\n", host_ports);


	singsing_set_scanmode( &fd, SINGSING_NODUP_SCAN );
	singsing_set_scanmode( &fd, SINGSING_SEGMENT_SCAN );
	 

	fprintf( stderr, " Starting scan...\n\n");

	if( singsing_init(&fd) < 0 ) {
		usage(argv[0]);
	}

	tty_raw();

        do {
                cur_res = singsing_get_result(&fd);
                if( cur_res != NULL ) {
                        result.s_addr = ntohl(cur_res->ip);

			if( cur_res->type == SINGSING_OPEN )
                        	printf(" zucca open %s:%u\n",inet_ntoa( result ), cur_res->port );
			else
                        	printf(" zucca close %s:%u\n",inet_ntoa( result ), cur_res->port );

                        free(cur_res);
                } else {
                        usleep(300000);

			if( getch() > 0 ) {
				singsing_get_status(&fd, &current_status);
//expected end time 
//num porta : tot porta = diff : x
    // Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz"
    //ts = *localtime(&now);
    //strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    //printf("%s\n", buf);
				cur = current_status.init_time;
				cur += difftime(current_status.current_time, current_status.init_time) * current_status.total_port / current_status.current_port;
			
				ts = *localtime(&cur);
				
				strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
				
				fprintf(stderr," stats: %lu%% expected end at %s\n", \
				100 * current_status.current_port / current_status.total_port, \
				buf);

			}
		}

        } while( singsing_scanisfinished(&fd) != 2 || cur_res != NULL);

	endtime = time( NULL );
	
	singsing_get_status(&fd, &current_status);

	fprintf( stderr, " %lu ports scanned in %.0lf seconds\n", current_status.total_port, difftime(endtime, current_status.init_time));

	tty_normal();

	singsing_destroy(&fd);	

	exit( EXIT_SUCCESS );
}


/* Parse /etc/services */
int parse_system_service( struct singsing_descriptor * fd )
{
	struct servent * tmp;

	while( ( tmp = getservent()) != NULL ) {
		if( strcmp( tmp->s_proto, "tcp") == 0 ) {

			singsing_add_port( fd, ntohs(tmp->s_port) );

			host_ports++;
		}
	}

	endservent();

	return 0;
} 

/* Parse port command line */
void parse_port( struct singsing_descriptor * fd, char * ports )
{
	char * tmp;
	long port;

	if( ( tmp = strchr( ports, ',')	) != NULL ) {
		*tmp = 0;
		tmp++;

		parse_port( fd, ports );
		parse_port( fd, tmp );

		return; 
	}

	if( ( tmp = strchr( ports, '-') ) != NULL ) {
		char number[10];
		int i;

		*tmp = 0;
		tmp++;

		for( i = atol( ports ); i <= atol(tmp); i++) {
			snprintf( number, sizeof(number), "%d", i);
			parse_port( fd, number );
		}
		return;
	}

        if( (port = atol(ports)) > 0 ) {
		singsing_add_port( fd, port );
                host_ports++;

                return;
        } 

	return;
}

void usage( char * argv0 )
{
	fprintf( stderr, " Usage:\n");
	fprintf( stderr, "  %s -h <arg> -i <arg> [-b <arg>] [-p <arg>] [-c]\n\n",argv0);
	fprintf( stderr, " -h Host/s to scan  (ex 192.168.0.0/24)\n");
	fprintf( stderr, " -i Interface\n");
	fprintf( stderr, " -b Usable bandwidth in KB (Default 15)\n");
	fprintf( stderr, " -p Ports (ex 22,23,40-50,99)\n");   
 	fprintf( stderr, " -c Display closed ports\n\n");

	exit( EXIT_FAILURE );
}

void tty_normal(void)
{
        tcsetattr(0, TCSADRAIN, &savetty);
}

void tty_raw(void)
{
	struct termios tty;
        tcgetattr(0, &savetty);
        tcgetattr(0, &tty);
        tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
        tty.c_cc[VTIME] = 0;
        tty.c_cc[VMIN] = 0;
        tcsetattr(0, TCSADRAIN, &tty);
}

int getch (void)
{
	char buf[2];
        if (read (0, buf, 1)) {
                return buf[0];
        }
        return -1;
}

