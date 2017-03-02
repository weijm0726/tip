obj-$(CONFIG_CRYPTO_DEV_SP_DD) += ccp.o
ccp-objs := sp-dev.o sp-platform.o
ccp-$(CONFIG_PCI) += sp-pci.o
ccp-$(CONFIG_CRYPTO_DEV_CCP) += ccp-dev.o \
	    ccp-ops.o \
	    ccp-dev-v3.o \
	    ccp-dev-v5.o \
	    ccp-dmaengine.o

obj-$(CONFIG_CRYPTO_DEV_CCP_CRYPTO) += ccp-crypto.o
ccp-crypto-objs := ccp-crypto-main.o \
		   ccp-crypto-aes.o \
		   ccp-crypto-aes-cmac.o \
		   ccp-crypto-aes-xts.o \
		   ccp-crypto-sha.o
