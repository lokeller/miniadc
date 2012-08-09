CC = /home/lokeller/Software/CodeSourcery2007/bin/arm-none-linux-gnueabi-gcc

CFLAGS=-g -I/home/lokeller/Workspaces/MiniADC/deps_binary/include
LDFLAGS = -L/home/lokeller/Workspaces/MiniADC/deps_binary/lib  -lgnutls  -lnettle -lgmp -lhogweed -lp11-kit -lSegFault

miniadc : miniadc.o tiger/tiger.o tiger/sboxes.c ../deps_binary/lib/libbz2.a

clean : 
	rm -rf *.o miniadc
