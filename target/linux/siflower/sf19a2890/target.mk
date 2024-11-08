ARCH:=mipsel
SUBTARGET:=sf19a2890
BOARDNAME:=Siflower SF19A2890 based boards
FEATURES+=fpu small_flash low_mem
CPU_TYPE:=24kc
CPU_SUBTYPE:=24kf

KERNELNAME:=vmlinux

define Target/Description
	Build firmware images for Siflower SF19A2890 based boards.
endef
