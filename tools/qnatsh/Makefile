top_srcdir=..
LIBDIR  = ../lib
INCDIR 	= .
LIBZ	= ./lib
INCDIR_COM = ../include

targets=qnatsh

CC	= gcc
CFLAGS	= -Wall -rdynamic -g #-O2
CFLAGS  += -Wno-unused -Wno-missing-braces #-Wno-unused-function
DEFS	= -DHAVE_CONFIG_H

INCZEBRA	= $(INCDIR)/lib
INCPFLOW	= $(INCDIR_COM)/pflow
INCLUDE		= -I$(INCZEBRA) -I. -I$(INCPFLOW)
LIBS		= -L$(LIBDIR) -L$(LIBZ) -lreadline -lm -lpthread 
ZEBRA_LIBS	= -lrt -lcrypt
all: $(targets)

deps_objs= 	\
		nsh_config.o \
	      	nsh_main.o \
	       	nsh_user.o \
		nsh_cmd.o \
		nsh_serv.o \
		msg.o \
		nsh.o \
		${LIBZ}/command.o \
		${LIBZ}/linklist.o \
                ${LIBZ}/log.o \
                ${LIBZ}/memory.o \
                ${LIBZ}/memtypes.o \
                ${LIBZ}/prefix.o \
                ${LIBZ}/str.o \
                ${LIBZ}/vector.o \
                ${LIBZ}/vty.o \
                ${LIBZ}/buffer.o \
                ${LIBZ}/sockunion.o \
                ${LIBZ}/privs.o \
                ${LIBZ}/network.o \
                ${LIBZ}/filter.o \
                ${LIBZ}/md5.o \

deps_libs=

.c.o:
	$(CC) -c $(CFLAGS) ${DEFS} $(INCLUDE) $< -o $@

$(targets): $(deps_objs) $(deps_libs)
	${CC} -o $@ $^ ${CFLAGS} ${DEFS} $(LIBS) $(ZEBRA_LIBS)

clean:
	-rm -f $(targets) $(deps_objs)

.PHONY: all clean install
