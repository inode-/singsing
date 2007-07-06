#  * $Id::                                                                  $: *
all:
	@echo "Please use one of the following make choice:"
	@echo "make linux"
	@echo "make solaris"
	@echo "make mac"

linux: zucca.c ssh_scan.c ../singsing.c ../singsing.h ../singsing_p.h
	gcc -o zucca zucca.c ../singsing.c -I../ -lpcap -lpthread -Wall
	gcc -o ssh_scan ssh_scan.c ../singsing.c -I../ -lpcap -lpthread -Wall

solaris: zucca.c ssh_scan.c ../singsing.c ../singsing.h ../singsing_p.h
	gcc -o zucca zucca.c ../singsing.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o ssh_scan ssh_scan.c ../singsing.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall

mac: zucca.c ssh_scan.c ../singsing.c ../singsing.h ../singsing_p.h
	gcc -o zucca zucca.c ../singsing.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o ssh_scan ssh_scan.c ../singsing.c -I../ -DMAC -lpcap -lpthread -Wall

