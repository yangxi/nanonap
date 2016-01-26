KDIR = /lib/modules/`uname -r`/build
obj-m := c1latency.o
M := make -C ${KDIR} M=`pwd`

all:
	${M} modules


user:
	gcc -o test_latency ./test_latency.c -lpthread -lpfm -pthread
	gcc -o batch ./batch.c -lpthread -lpfm -pthread
	gcc -o test_mutex ./test_mutex.c -lpthread -lpfm -pthread
	gcc -o ./nanosleep ./nanosleep.c -lpthread -lpfm -pthread -lrt
	gcc -o ./observe_idle ./observe_idle.c -lpthread -lpfm -pthread -lrt
