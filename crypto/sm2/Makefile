#
# OpenSSL/crypto/sm2/Makefile
#

DIR=    sm2
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
LIBSRC=sm2_lib.c sm2_err.c
LIBOBJ=sm2_lib.o sm2_err.o

SRC= $(LIBSRC)

EXHEADER= sm2.h
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

sm2_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
sm2_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
sm2_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm2_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
sm2_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
sm2_lib.o: ../../include/openssl/lhash.h ../../include/openssl/objects.h
sm2_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/opensslconf.h
sm2_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm2_lib.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
sm2_lib.o: ../../include/openssl/symhacks.h sm2.h sm2_lib.c
ec_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ec_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ec_err.o: ../../include/openssl/sm2.h ../../include/openssl/err.h
ec_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
ec_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ec_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ec_err.o: ../../include/openssl/symhacks.h sm2_err.c

