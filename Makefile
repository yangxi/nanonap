KDIR = /lib/modules/`uname -r`/build
obj-m := c1latency.o
M := make -C ${KDIR} M=`pwd`

all:
	${M} modules


user:
	gcc -o test_latency ./test_latency.c -lpthread -lpfm -pthread
