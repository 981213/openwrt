
define Device/Default
  PROFILES = Default $$(DEVICE_NAME)
  BLOCKSIZE := 64k
  KERNEL = kernel-bin | lzma
  KERNEL_INITRAMFS = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd | pad-to 128k
  KERNEL_LOADADDR := 0x20000000
  FILESYSTEMS := squashfs
  DEVICE_DTS_DIR := ../dts
  IMAGES := sysupgrade.bin
  IMAGE/sysupgrade.bin = append-kernel | fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb external-static-with-rootfs | pad-rootfs | append-metadata
endef


define Device/siflower_sf21a6826-evb
  DEVICE_VENDOR := Siflower
  DEVICE_MODEL := SF21A6826 EVB
  DEVICE_DTS := sf21a6826_evb
  SUPPORTED_DEVICES := siflower,sf21a6826-evb
endef
TARGET_DEVICES += siflower_sf21a6826-evb

define Device/siflower_sf21h8898-bpi
  DEVICE_VENDOR := Siflower
  DEVICE_MODEL := SF21H8898 BPI
  DEVICE_DTS := sf21h8898_bpi
  SUPPORTED_DEVICES := siflower,sf21h8898-bpi
endef
TARGET_DEVICES += siflower_sf21h8898-bpi
