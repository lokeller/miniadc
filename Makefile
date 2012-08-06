CFLAGS=-g
LDFLAGS = -lgnutls -lbz2 

miniadc : miniadc.o tiger/tiger.o tiger/sboxes.c

clean : 
	rm -rf *.o miniadc
