include $(TOPDIR)/rules.mk

PKG_NAME:=jitterentropy-rustrngd
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=BSD-3-Clause
PKG_MAINTAINER:=https://github.com/stoickish

# Jitterentropy C library — bundled and statically linked.
# -O0 is mandatory: optimization eliminates the timing jitter that provides entropy.
JENT_LIB_NAME:=jitterentropy-library
JENT_LIB_VERSION:=3.6.0
JENT_LIB_SOURCE:=$(JENT_LIB_NAME)-$(JENT_LIB_VERSION).tar.gz
JENT_LIB_SOURCE_URL:=https://github.com/smuellerDD/jitterentropy-library/archive/refs/tags/

# TODO: update hash after first successful download:
#   sha256sum $(DL_DIR)/$(JENT_LIB_SOURCE)
JENT_LIB_HASH:=e2af325cdc7d951a66af782fad4bcdd622e9d8355dd024b7562e2f8b3f6079cd

define Download/jitterentropy-library
  FILE:=$(JENT_LIB_SOURCE)
  URL:=$(JENT_LIB_SOURCE_URL)
  URL_FILE:=v$(JENT_LIB_VERSION).tar.gz
  HASH:=$(JENT_LIB_HASH)
endef
$(eval $(call Download,jitterentropy-library))

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/jitterentropy-rustrngd
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Jitter Entropy RNG Daemon (Rust, SP800-90B)
  URL:=https://github.com/stoickish/openwrt-pkgs
endef

define Package/jitterentropy-rustrngd/description
  Rust RNG daemon that feeds entropy into /dev/random using the jitterentropy
  library as its source. Designed to replace urngd. Operates in SP800-90B /
  FIPS-140 compliant mode. Injects 256 bits on startup, then reseeds at an
  interval derived from CPU speed: interval_secs = 2^44 / cpu_hz.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
	mkdir -p $(PKG_BUILD_DIR)/jitterentropy-library
	$(TAR) -xzf $(DL_DIR)/$(JENT_LIB_SOURCE) \
		-C $(PKG_BUILD_DIR)/jitterentropy-library \
		--strip-components=1
endef

define Package/jitterentropy-rustrngd/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/bin/$(PKG_NAME) \
		$(1)/sbin/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) \
		./files/$(PKG_NAME).init \
		$(1)/etc/init.d/$(PKG_NAME)
endef

$(eval $(call RustBinPackage,jitterentropy-rustrngd))
$(eval $(call BuildPackage,jitterentropy-rustrngd))
