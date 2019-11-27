# 
# QNAT is a software NAT based on DPDK and DPVS.
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 

#
# Makefile for QNAT
#

#DEBUG := 1		# enable for debug

TARGET := qnat

# same path of THIS Makefile
SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

include $(SRCDIR)/dpdk.mk
include $(SRCDIR)/config.mk

INCDIRS += -I $(SRCDIR)/../include

# for dpvs main program.
CFLAGS += -D __DPVS__

CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes

ifeq ($(DEBUG),)
	CFLAGS += -O3 -DCONFIG_NETOPS_CONN_THRESH -DCONFIG_NETOPS_ACL_RANGE -DCONFIG_NETOPS_BYPASS_ROUTING
	#CFLAGS += -O0 -g -DCONFIG_NETOPS_CONN_THRESH -DCONFIG_NETOPS_ACL_RANGE -DCONFIG_NETOPS_BYPASS_ROUTING
else
	#CFLAGS += -g -O0 -D DEBUG
	CFLAGS += -g -O0 -D DEBUG -DCONFIG_NETOPS_CONN_THRESH -DCONFIG_NETOPS_ACL_RANGE -DCONFIG_NETOPS_BYPASS_ROUTING
endif

LIBS += -lpthread

CFLAGS += $(INCDIRS) $(LIBS)

OBJS := $(shell find $(SRCDIR) -name '*.c' | sort)
OBJS := $(patsubst %.c,%.o,$(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@
	@echo "  $(notdir $@)"

%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@
	@echo "  $(notdir $@)"

clean:
	find $(SRCDIR) -name '*.o' | xargs rm -f
	rm -f ./$(TARGET)

install:
	install -m 744 $(TARGET) $(INSDIR)
