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
MAKE	= make
CC 	= gcc
LD 	= ld

SUBDIRS = src tools

INSDIR  = /usr/bin
export INSDIR

export KERNEL   = $(shell /bin/uname -r)

all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:all
	-mkdir -p $(INSDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install || exit 1; done
	mkdir -p /etc/qnat/
	\cp config/qnat.conf config/qnatcfg.conf.sample config/qnat_blk.conf config/logo.conf /etc/qnat

