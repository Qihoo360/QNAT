# Makefile for libipvs

CC		= gcc
CFLAGS		= -g -O2  -I/usr/src/linux/include -I/usr/src/linux/include -DLIBIPVS_DONTUSE_NL -Wall -Wunused

CFLAGS += -I ../../../../include
CFLAGS += -I ./libsockopt

export OBJS += libipvs.a

STATIC_LIB	= libipvs.a

all:		$(STATIC_LIB)

test: sockopt.o test.o
		$(CC) $(CFLAGS) -o $@ $^

$(STATIC_LIB):	sockopt.o libipvs.o ip_vs_nl_policy.o
		ar rv $@ $^
		rm $^

%.o:		%.c
		$(CC) $(CFLAGS) -c -o $@ $<

clean:
		rm -f *.[ao] *~ *.orig *.rej core

distclean:	clean
