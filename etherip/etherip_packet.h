/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/* etherip_packet.h: EtherIP (RFC 3378) packet format */

#ifndef included_etherip_packet_h
#define included_etherip_packet_h

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/* RFC 3378 §2: 4 bit version (3) followed by 12 reserved bits (0) */
#define ETHERIP_VERSION	     3
#define ETHERIP_HEADER_VALUE 0x3000

STATIC_ASSERT ((ETHERIP_HEADER_VALUE >> 12) == ETHERIP_VERSION,
	       "EtherIP header value must carry the EtherIP version");

/**
 * @brief EtherIP header. Written and compared as a whole 16 bit word
 * instead of bitfields so that the layout does not depend on the host
 * byte order.
 */
typedef CLIB_PACKED (struct {
  /* version and reserved bits, network byte order */
  u16 ver_res;
}) etherip_header_t;

STATIC_ASSERT_SIZEOF (etherip_header_t, 2);

/**
 * @brief IPv4 and EtherIP header.
 */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  etherip_header_t etherip;
}) ip4_and_etherip_header_t;

STATIC_ASSERT_SIZEOF (ip4_and_etherip_header_t, 22);

/**
 * @brief IPv6 and EtherIP header.
 */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  etherip_header_t etherip;
}) ip6_and_etherip_header_t;

STATIC_ASSERT_SIZEOF (ip6_and_etherip_header_t, 42);

#endif /* included_etherip_packet_h */
