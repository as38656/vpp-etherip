# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Ryosuke Nakayama.

add_vpp_plugin(etherip
  SOURCES
  etherip.c
  node.c
  etherip_api.c
  interface.c
  plugin.c

  MULTIARCH_SOURCES
  node.c
  etherip.c

  INSTALL_HEADERS
  etherip.h
  etherip_packet.h
  error.def

  API_FILES
  etherip.api

)
