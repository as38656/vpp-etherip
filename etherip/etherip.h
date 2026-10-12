/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/* etherip.h: types/functions for EtherIP (RFC 3378) tunnels. */

#ifndef included_etherip_h
#define included_etherip_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_types.h>
#include <etherip/etherip_packet.h>

typedef enum
{
#define etherip_error(n, s) ETHERIP_ERROR_##n,
#include <etherip/error.def>
#undef etherip_error
  ETHERIP_N_ERROR,
} etherip_error_t;

/** outer TTL / hop limit used when none (0) is configured */
#define ETHERIP_DEFAULT_HOP_LIMIT 64

/**
 * @brief Key for a point-to-point EtherIP tunnel. Built from the receive
 * direction: src is the local endpoint (outer destination) and dst is the
 * remote endpoint (outer source).
 */
typedef struct etherip_tunnel_key_t_
{
  union
  {
    struct
    {
      ip46_address_t src;
      ip46_address_t dst;
      u32 fib_index;
      u8 is_ip6;
      u8 __pad[3];
    };
    u64 as_u64[5];
  };
} __clib_packed etherip_tunnel_key_t;

STATIC_ASSERT_SIZEOF (etherip_tunnel_key_t, 5 * sizeof (u64));

/**
 * @brief A representation of an EtherIP tunnel
 */
typedef struct
{
  /**
   * Required for pool_get_aligned
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * The tunnel's source/local address
   */
  ip46_address_t tunnel_src;
  /**
   * The tunnel's destination/remote address
   */
  fib_prefix_t tunnel_dst;
  /**
   * The FIB in which the src.dst address are present
   */
  u32 outer_fib_index;
  u32 hw_if_index;
  u32 sw_if_index;

  /**
   * The L2 midchain adjacency used for all transmitted frames
   */
  adj_index_t l2_adj_index;

  u32 dev_instance;  /* Real device instance in tunnel vector */
  u32 user_instance; /* Instance name being shown to user */

  /* outer header parameters */
  u8 hop_limit;
  u8 dscp;
  u8 set_df;
} etherip_tunnel_t;

/**
 * @brief Per thread data
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Identification of the next IPv4 outer header with DF=0 */
  u16 ip4_id;
} etherip_per_thread_data_t;

/**
 * @brief EtherIP related global data
 */
typedef struct
{
  /**
   * pool of tunnel instances
   */
  etherip_tunnel_t *tunnels;

  /**
   * Hash mapping etherip_tunnel_key_t to tunnel index
   */
  uword *tunnel_by_key;

  /**
   * Mapping from sw_if_index to tunnel index
   */
  u32 *tunnel_index_by_sw_if_index;

  /* Record used instances */
  uword *instance_used;

  /* per thread data, indexed by thread index */
  etherip_per_thread_data_t *per_thread_data;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /**
   * Accept received EtherIP packets. Off by default, as OpenBSD's
   * net.inet.etherip.allow.
   */
  bool allow;

  bool ip4_protocol_registered;
  bool ip6_protocol_registered;

  u16 msg_id_base;
} etherip_main_t;

extern etherip_main_t etherip_main;

extern vlib_node_registration_t etherip4_input_node;
extern vlib_node_registration_t etherip6_input_node;
extern vlib_node_registration_t etherip_encap_node;
extern vnet_device_class_t etherip_device_class;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u32 instance; /* ~0 for automatic allocation */
  ip46_address_t src, dst;
  u32 outer_table_id;
  u8 hop_limit; /* 0 for ETHERIP_DEFAULT_HOP_LIMIT */
  u8 dscp;
  u8 set_df;
} vnet_etherip_tunnel_add_del_args_t;

extern int vnet_etherip_tunnel_add_del (const vnet_etherip_tunnel_add_del_args_t *a,
					u32 *sw_if_indexp);
extern void vnet_etherip_set_allow (bool enable);

extern clib_error_t *etherip_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags);
extern void etherip_tunnel_stack (const etherip_tunnel_t *t);
extern void etherip_update_adj (const etherip_tunnel_t *t);

/* tunnel sw_if_index in a packet trace, "none" for ~0 */
format_function_t format_etherip_trace_tunnel;

static_always_inline int
etherip_tunnel_is_ip6 (const etherip_tunnel_t *t)
{
  return (FIB_PROTOCOL_IP6 == t->tunnel_dst.fp_proto);
}

static_always_inline etherip_tunnel_t *
etherip_tunnel_get_by_sw_if_index (u32 sw_if_index)
{
  etherip_main_t *em = &etherip_main;
  u32 ti;

  if (sw_if_index >= vec_len (em->tunnel_index_by_sw_if_index))
    return (NULL);

  ti = em->tunnel_index_by_sw_if_index[sw_if_index];
  if (~0 == ti)
    return (NULL);

  return (pool_elt_at_index (em->tunnels, ti));
}

static_always_inline void
etherip_mk_key4 (const ip4_address_t *src, const ip4_address_t *dst, u32 fib_index,
		 etherip_tunnel_key_t *key)
{
  clib_memset (key, 0, sizeof (*key));
  key->src.ip4.as_u32 = src->as_u32;
  key->dst.ip4.as_u32 = dst->as_u32;
  key->fib_index = fib_index;
}

static_always_inline void
etherip_mk_key6 (const ip6_address_t *src, const ip6_address_t *dst, u32 fib_index,
		 etherip_tunnel_key_t *key)
{
  clib_memset (key, 0, sizeof (*key));
  key->src.ip6.as_u64[0] = src->as_u64[0];
  key->src.ip6.as_u64[1] = src->as_u64[1];
  key->dst.ip6.as_u64[0] = dst->as_u64[0];
  key->dst.ip6.as_u64[1] = dst->as_u64[1];
  key->fib_index = fib_index;
  key->is_ip6 = 1;
}

static_always_inline int
etherip_key_is_equal (const etherip_tunnel_key_t *k1, const etherip_tunnel_key_t *k2)
{
  return ((k1->as_u64[0] == k2->as_u64[0]) && (k1->as_u64[1] == k2->as_u64[1]) &&
	  (k1->as_u64[2] == k2->as_u64[2]) && (k1->as_u64[3] == k2->as_u64[3]) &&
	  (k1->as_u64[4] == k2->as_u64[4]));
}

#endif /* included_etherip_h */
