# name of your application
APPLICATION = gnrc_border_router_rpl

CFLAGS += -DGATEWAY_IPV6_ADDR=\"2001:660:3207:400::64\"

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Default to using ethos for providing the uplink when not on native
UPLINK ?= ethos

# Check if the selected Uplink is valid
ifeq (,$(filter ethos slip cdc-ecm wifi ethernet,$(UPLINK)))
  $(error Supported uplinks are `ethos`, `slip`, `cdc-ecm`, `ethernet` and `wifi`)
endif

# Set the SSID and password of your WiFi network here
WIFI_SSID ?= "Your_WiFi_name"
WIFI_PASS ?= "Your_secure_password"

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for 6LoWPAN border router
USEMODULE += gnrc_sixlowpan_border_router_default
# Add a routing protocol
USEMODULE += gnrc_rpl
USEMODULE += auto_init_gnrc_rpl

# RPL config
# This RPL implementation currently only supports storing mode. That means, in order to have downwards routes to all nodes the storage space within gnrc_ipv6's Neighbor Information Base must be big enough to store information for each node.
# For a random topology of n nodes, to ensure you can reach every node from the root, set CONFIG_GNRC_IPV6_NIB_NUMOF == CONFIG_GNRC_IPV6_NIB_OFFL_NUMOF == n.
CFLAGS += -DCONFIG_GNRC_IPV6_NIB_NUMOF=50
CFLAGS += -DCONFIG_GNRC_IPV6_NIB_OFFL_NUMOF=50
# If you want to allow for alternative parents, increase the number of default routers in the NIB.
CFLAGS += -DCONFIG_GNRC_IPV6_NIB_DEFAULT_ROUTER_NUMOF=2

# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
USEMODULE += shell_cmd_gnrc_udp
# Add also the shell, some shell commands
USEMODULE += posix_sockets
USEMODULE += sock_udp
USEMODULE += posix_sleep
USEMODULE += posix_inet
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ps
USEMODULE += netstats_l2
USEMODULE += netstats_ipv6
USEMODULE += netstats_rpl

# Optionally include RPL as a routing protocol. When includede gnrc_uhcpc will
# configure the node as a RPL DODAG root when receiving a prefix.
#USEMODULE += gnrc_rpl

# Optionally include DNS support. This includes resolution of names at an
# upstream DNS server and the handling of RDNSS options in Router Advertisements
# to auto-configure that upstream DNS server.
#USEMODULE += sock_dns              # include DNS client
#USEMODULE += gnrc_ipv6_nib_dns     # include RDNSS option handling

# When using a regular network uplink we should use DHCPv6
ifneq (,$(filter cdc-ecm wifi ethernet,$(UPLINK))$(REUSE_TAP))
  PREFIX_CONF ?= dhcpv6
else
  PREFIX_CONF ?= uhcp
endif

# Check if the selected method for prefix configuration is valid
ifeq (,$(filter dhcpv6 uhcp auto_subnets static,$(PREFIX_CONF)))
  $(error Supported methods for prefix configuration are `dhcpv6`, `uhcp` `static` and `auto_subnets`)
endif

ifeq (dhcpv6,$(PREFIX_CONF))
  # include DHCPv6 client for 6LoWPAN border router
  USEMODULE += gnrc_dhcpv6_client_6lbr
else ifeq (uhcp,$(PREFIX_CONF))
  # include UHCP client
  USEMODULE += gnrc_uhcpc
else ifeq (auto_subnets,$(PREFIX_CONF))
  USEMODULE += gnrc_ipv6_auto_subnets_simple
else ifeq (static,$(PREFIX_CONF))
  IPV6_ADDR ?= 2001:db8:1::1
# Only set this if the default router does not send router advertisements
# IPV6_DEFAULT_ROUTER ?= fe80::1
  USEMODULE += gnrc_ipv6_static_addr

  # configure static DNS server
  ifneq (,$(filter sock_dns,$(USEMODULE)))
    USEMODULE += auto_init_sock_dns
  endif
endif

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# Ethos/native TAP interface and UHCP prefix can be configured from make command
TAP ?= tap0
ifneq (,$(filter dhcpv6 auto_subnets,$(PREFIX_CONF)))
  # with DHCPv6 the 64-bit delegated prefixes are generated from a shorter
  # configured prefix.
  IPV6_PREFIX ?= 2001:db8::/32
else
  # UHCP advertises the prefix as is.
  IPV6_PREFIX ?= 2001:db8::/64
endif

# MODULE DEPENDENT CONFIGURATION IMPORT
# =====================================
# use ethos (ethernet over serial) or SLIP (serial-line IP) for network
# communication and stdio over UART, but not on native, as native has a tap
# interface towards the host.
ifeq (,$(filter native,$(BOARD)))
  ifeq (slip,$(UPLINK))
    # SLIP baudrate and UART device can be configured from make command
    SLIP_BAUDRATE ?= 115200
    include $(CURDIR)/Makefile.slip.conf
  else ifeq (ethos,$(UPLINK))
    # ethos baudrate can be configured from make command
    ETHOS_BAUDRATE ?= 115200
    include $(CURDIR)/Makefile.ethos.conf
  else ifeq (cdc-ecm,$(UPLINK))
    include $(CURDIR)/Makefile.cdc-ecm.conf
  else ifeq (wifi,$(UPLINK))
    # SSID and Password need to be configured
    include $(CURDIR)/Makefile.wifi.conf
  endif
else
  # The number of native (emulated) ZigBee/6LoWPAN devices
  ZEP_DEVICES ?= 1
  include $(CURDIR)/Makefile.native.conf
endif

# As there is an 'Kconfig' we want to explicitly disable Kconfig by setting
# the variable to empty
SHOULD_RUN_KCONFIG ?=

include $(RIOTBASE)/Makefile.include

# Compile-time configuration for DHCPv6 client (needs to come after
# Makefile.include as this might come from Kconfig)
ifeq (dhcpv6,$(PREFIX_CONF))
  ifndef CONFIG_GNRC_DHCPV6_CLIENT_6LBR_STATIC_ROUTE
    ifeq (1,$(STATIC_ROUTES))
      CFLAGS += -DCONFIG_GNRC_DHCPV6_CLIENT_6LBR_STATIC_ROUTE=1
      # CONFIG_GNRC_DHCPV6_CLIENT_6LBR_STATIC_ROUTE=1 requires one more address
      # for `fe80::2`.
      CFLAGS += -DCONFIG_GNRC_NETIF_IPV6_ADDRS_NUMOF=3
    endif
  endif
else ifeq (static,$(PREFIX_CONF))
  ifndef CONFIG_GNRC_IPV6_STATIC_ADDR
    CFLAGS += -DCONFIG_GNRC_IPV6_STATIC_ADDR=\"$(IPV6_ADDR)\"
  endif
  ifndef CONFIG_GNRC_IPV6_STATIC_PREFIX
    CFLAGS += -DCONFIG_GNRC_IPV6_STATIC_PREFIX=\"$(IPV6_PREFIX)\"
  endif
  ifndef CONFIG_GNRC_IPV6_STATIC_DEFAULT_ROUTER
    CFLAGS += -DCONFIG_GNRC_IPV6_STATIC_DEFAULT_ROUTER=\"$(IPV6_DEFAULT_ROUTER)\"
  endif
endif


.PHONY: host-tools

host-tools:
	$(Q)env -u CC -u CFLAGS $(MAKE) -C $(RIOTTOOLS)

# define native specific targets to only run UHCP daemon when required
ifneq (,$(filter native,$(BOARD)))
ifeq (uhcp,$(PREFIX_CONF))
.PHONY: uhcpd-daemon

uhcpd-daemon: host-tools
	$(RIOTTOOLS)/uhcpd/bin/uhcpd $(TAP) $(IPV6_PREFIX) &
endif
endif

ifeq (slip,$(UPLINK))
sliptty:
	$(Q)env -u CC -u CFLAGS $(MAKE) -C $(RIOTTOOLS)/sliptty
endif

# Set a custom channel if needed
include $(RIOTMAKE)/default-radio-settings.inc.mk
