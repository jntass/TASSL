#
# OpenSSL/crypto/sm3/Makefile
#

DIR=    sm3
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=sm3.c sm3_one.c
LIBOBJ=sm3.o sm3_one.o

SRC= $(LIBSRC)

EXHEADER= sm3.h
HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

sm3.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm3.o: ../../include/openssl/sm3.h ../../include/openssl/opensslconf.h
sm3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm3.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
sm3.o: ../../include/openssl/symhacks.h ../md32_common.h sm3.c
sm3_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm3_one.o: ../../include/openssl/sm3.h ../../include/openssl/opensslconf.h
sm3_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm3_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
sm3_one.o: ../../include/openssl/symhacks.h sm3_one.c

