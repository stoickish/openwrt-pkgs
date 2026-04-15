include $(TOPDIR)/rules.mk

PKG_NAME:=filogic-optimizer
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
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
  - WED hardware flow offload via nftables FLOWOFFLOAD (all platforms)
  - Aggressive fan trip-point profile (platforms with 6-zone thermal only,
    detected at runtime — no platform-specific build required)
endef

# No compilation needed — shell script package
define Build/Compile
endef

define Package/filogic-optimizer/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/filogic-optimizer $(1)/usr/sbin/filogic-optimizer
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/filogic-optimizer.init $(1)/etc/init.d/filogic-optimizer
endef

$(eval $(call BuildPackage,filogic-optimizer))
