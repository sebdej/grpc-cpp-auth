all: cert_chain.h private_key.h signing_key.h

%.h : %.pem
	xxd -i $< > $@

%.h : %.bin
	xxd -i $< > $@