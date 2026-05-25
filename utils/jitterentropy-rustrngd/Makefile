include $(TOPDIR)/rules.mk

PKG_NAME:=jitterentropy-rustrngd
PKG_VERSION:=0.2.0
PKG_RELEASE:=14

PKG_LICENSE:=BSD-3-Clause
PKG_MAINTAINER:=https://github.com/stoickish

# Jitterentropy C library — bundled and statically linked.
# -O0 is mandatory: optimization eliminates the timing jitter that provides entropy.
JENT_LIB_NAME:=jitterentropy-library
JENT_LIB_VERSION:=3.7.0
JENT_LIB_SOURCE:=$(JENT_LIB_NAME)-$(JENT_LIB_VERSION).tar.gz
JENT_LIB_SOURCE_URL:=https://github.com/smuellerDD/jitterentropy-library/archive/refs/tags/
JENT_LIB_URL_FILE:=v$(JENT_LIB_VERSION).tar.gz

JENT_LIB_HASH:=f5eaccc9d2977c83308651be9379f09f34348398f419e8f8b5bbd95928c777ed

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Download/jitterentropy-library
  FILE:=$(JENT_LIB_SOURCE)
  URL:=$(JENT_LIB_SOURCE_URL)
  URL_FILE:=$(JENT_LIB_URL_FILE)
  HASH:=$(JENT_LIB_HASH)
endef
$(eval $(call Download,jitterentropy-library))

define Package/jitterentropy-rustrngd
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Jitter Entropy RNG Daemon (Rust, SP800-90B)
  URL:=https://github.com/stoickish/openwrt-pkgs
endef

define Package/jitterentropy-rustrngd/description
  Rust RNG daemon that feeds entropy into /dev/random using the jitterentropy
  library as its source. Designed to replace urngd. Operates in SP800-90B /
  FIPS-140 compliant mode. Injects 384 bits on startup, then reseeds every 512 seconds.
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

# Post-build: compute HMAC-SHA3-256 integrity digest over the .text section
# and patch it into the binary's integrity block.  Must run AFTER Build/Compile/Cargo
# (which produces the binary at PKG_INSTALL_DIR) and BEFORE BuildPackage uses it.
JENT_RNGRD_VERSION:=$(PKG_VERSION)
JENT_RNGRD_RELEASE:=$(PKG_RELEASE)
export JENT_RNGRD_VERSION JENT_RNGRD_RELEASE JENT_LIB_VERSION

define Build/Compile
	+$$(call Build/Compile/Cargo)
	python3 $(PKG_BUILD_DIR)/scripts/patch-integrity.py $(PKG_INSTALL_DIR)/bin/$(PKG_NAME)
endef

$(eval $(call BuildPackage,jitterentropy-rustrngd))
