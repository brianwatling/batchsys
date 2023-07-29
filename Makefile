obj-m += batchsys.o

ccflags-y += -Wall -Werror -O3

all: module libbatchsys.a test

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f test

libbatchsys.a: CFLAGS += -g -O3
libbatchsys.a: batchsysuser.o batchsys.h
	ar rcs $@ $<

test: CFLAGS += -g -O3
test: LDFLAGS += -ldl -lrt
test: test.c libbatchsys.a
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
