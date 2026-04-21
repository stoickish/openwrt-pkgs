include $(TOPDIR)/rules.mk

PKG_NAME:=filogic-optimizer
PKG_VERSION:=0.1.0
PKG_RELEASE:=2
PKG_LICENSE:=BSD-3-Clause
PKG_MAINTAINER:=https://github.com/stoickish

include $(INCLUDE_DIR)/package.mk

define Package/filogic-optimizer
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Boot-time optimizer for Filogic-based routers
  URL:=https://github.com/stoickish/openwrt-pkgs
endef

define Package/filogic-optimizer/description
  Applies boot-time performance and power optimizations for Filogic-based
  OpenWrt routers (MT7981, MT7986, MT7988, etc.).

  - PCIe ASPM powersave (all platforms)
  - Aggressive fan trip-point profile (SDG-8733 only, detected at runtime)
  - WED hardware flow offload via nftables FLOWOFFLOAD (all platforms),
    applied via hotplug when the lan interface comes up — no polling
endef

# No compilation needed — shell script package
define Build/Compile
endef

define Package/filogic-optimizer/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/filogic-optimizer $(1)/usr/sbin/filogic-optimizer
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/filogic-optimizer.init $(1)/etc/init.d/filogic-optimizer
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/filogic-wed-offload.hotplug \
		$(1)/etc/hotplug.d/iface/20-filogic-wed-offload
endef

$(eval $(call BuildPackage,filogic-optimizer))
