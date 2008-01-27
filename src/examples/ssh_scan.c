/*****************************************************************************
 * Copyright (c) 2007, Agazzini Maurizio - inode@mediaservice.net            *
 * All rights reserved.                                                      *
 *                                                                           *
 * ssh_scan.c                                                                *
 *                                                                           *
 * * $Id::                                                                $: *
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
 * THIS SOFTWARE IS PROVIDED BY Agazzini Maurizio ``AS IS'' AND ANY          *
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED *
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE    *
 * DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY        *
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        *
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   *
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     *
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       *
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  *
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE           *
 * POSSIBILITY OF SUCH DAMAGE.                                               *
 *****************************************************************************/

#include "singsing.h"

#define NAME "SSH syn scanner"
#define VERSION "0.1"

#define DEBUG 1

void usage( char * argv );

int main(int argc, char ** argv)
{
	char * target = NULL;
	char * device = NULL;
	char opt;
	struct in_addr result;
        time_t start_time;
        time_t end_time;

	struct singsing_result_queue * cur_res;

        struct singsing_descriptor fd;

        singsing_create(&fd);

	while((opt = getopt(argc, argv, "i:h:")) != -1)
	{
		switch (opt)
		{
			case 'i':
				device = optarg;
				break;
			case 'h':
				target = optarg;
				break;
			default:
				usage( argv[0] );
		}
	}

	if( target == NULL || device == NULL )
		usage( argv[0] );

	singsing_set_scan_interface( &fd, device );

	singsing_set_scan_host( &fd, target );

	singsing_add_port( &fd, 22 );

	fprintf( stderr, "Starting scan...\n");

	start_time = time(NULL);

	singsing_init(&fd);

	do {
		cur_res = singsing_get_result(&fd);
		if( cur_res != NULL ) {
			result.s_addr = ntohl(cur_res->ip);
			printf(" SSH port opened on %s\n",inet_ntoa( result ) );
			
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
	fprintf(stderr, "\n Usage: %s -i <arg> -h <arg>\n", argv);
	fprintf(stderr, "\t-i Interface\n");
	fprintf(stderr, "\t-h Target (CIDR format)\n");
	exit(0);
}
