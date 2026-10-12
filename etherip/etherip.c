/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/* etherip.c: EtherIP device class, encap and adjacency handling */

#include <vnet/vnet.h>
#include <vnet/adj/adj_midchain.h>
#include <vppinfra/random.h>
#include <etherip/etherip.h>

#ifndef CLIB_MARCH_VARIANT
etherip_main_t etherip_main;
#endif /* CLIB_MARCH_VARIANT */

/* Packet trace structure */
typedef struct
{
  /* tunnel sw_if_index, same meaning as in the RX trace */
  u32 tunnel_sw_if_index;

  /* pkt length */
  u32 length;

  /* tunnel ip addresses */
  ip46_address_t src;
  ip46_address_t dst;
} etherip_tx_trace_t;

extern u8 *format_etherip_tx_trace (u8 *s, va_list *args);

#ifndef CLIB_MARCH_VARIANT
u8 *
format_etherip_trace_tunnel (u8 *s, va_list *args)
{
  u32 sw_if_index = va_arg (*args, u32);

  if (~0 == sw_if_index)
    return format (s, "none");

  return format (s, "%u", sw_if_index);
}

u8 *
format_etherip_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  etherip_tx_trace_t *t = va_arg (*args, etherip_tx_trace_t *);

  s = format (s, "EtherIP: tunnel %U len %d src %U dst %U", format_etherip_trace_tunnel,
	      t->tunnel_sw_if_index, t->length, format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

static u8 *
etherip_build_rewrite (const etherip_tunnel_t *t)
{
  ip4_and_etherip_header_t *h4;
  ip6_and_etherip_header_t *h6;
  etherip_header_t *eip;
  u8 *rewrite = NULL;

  if (!etherip_tunnel_is_ip6 (t))
    {
      vec_validate (rewrite, sizeof (*h4) - 1);
      h4 = (ip4_and_etherip_header_t *) rewrite;
      eip = &h4->etherip;
      h4->ip4.ip_version_and_header_length = 0x45;
      h4->ip4.ttl = t->hop_limit;
      h4->ip4.protocol = IP_PROTOCOL_ETHERIP;
      /* ECN bits stay 0 (RFC 9601 §4) */
      ip4_header_set_dscp (&h4->ip4, t->dscp);
      if (t->set_df)
	ip4_header_set_df (&h4->ip4);
      /* fixup ip4 header length and checksum after-the-fact */
      h4->ip4.src_address.as_u32 = t->tunnel_src.ip4.as_u32;
      h4->ip4.dst_address.as_u32 = t->tunnel_dst.fp_addr.ip4.as_u32;
      h4->ip4.checksum = ip4_header_checksum (&h4->ip4);
    }
  else
    {
      vec_validate (rewrite, sizeof (*h6) - 1);
      h6 = (ip6_and_etherip_header_t *) rewrite;
      eip = &h6->etherip;
      /* flow label 0, ECN bits 0 (RFC 9601 §4) */
      h6->ip6.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (6 << 28);
      ip6_set_dscp_network_order (&h6->ip6, t->dscp);
      /* With set-df the fixup keeps the buffer from being locally
       * originated so that ip6-rewrite does not fragment it; ip6-rewrite
       * then decrements the hop limit, so add the one it takes away.
       * Interim: a hop limit of 255 still leaves as 254. */
      if (t->set_df)
	h6->ip6.hop_limit = clib_min ((u32) t->hop_limit + 1, 255);
      else
	h6->ip6.hop_limit = t->hop_limit;
      h6->ip6.protocol = IP_PROTOCOL_ETHERIP;
      /* fixup ip6 payload length after-the-fact */
      h6->ip6.src_address.as_u64[0] = t->tunnel_src.ip6.as_u64[0];
      h6->ip6.src_address.as_u64[1] = t->tunnel_src.ip6.as_u64[1];
      h6->ip6.dst_address.as_u64[0] = t->tunnel_dst.fp_addr.ip6.as_u64[0];
      h6->ip6.dst_address.as_u64[1] = t->tunnel_dst.fp_addr.ip6.as_u64[1];
    }

  eip->ver_res = clib_host_to_net_u16 (ETHERIP_HEADER_VALUE);

  return (rewrite);
}

static void
etherip4_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0, const void *data)
{
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* The outer header is originated here. Without this flag ip4-rewrite
   * decrements the configured TTL; OpenBSD sends it unchanged. Whether
   * ip4-rewrite may fragment is still decided by the DF bit. */
  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  /* DF=0: a fragmentable datagram must not repeat its ID for the same
   * src/dst/protocol (RFC 6864 §4.3); OpenBSD uses ip_randomid(). With
   * set-df the datagram is atomic and the ID stays 0 (RFC 6864 §4.1). */
  if (!pointer_to_uword (data))
    {
      etherip_per_thread_data_t *ptd =
	vec_elt_at_index (etherip_main.per_thread_data, vm->thread_index);
      ip0->fragment_id = clib_host_to_net_u16 (ptd->ip4_id++);
    }

  /* Fixup the checksum and len fields in the EtherIP tunnel encap
   * that was applied at the midchain node */
  ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip0->checksum = ip4_header_checksum (ip0);
}

static void
etherip6_fixup (vlib_main_t *vm, const ip_adjacency_t *adj, vlib_buffer_t *b0, const void *data)
{
  ip6_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* IPv6 has no DF bit: allow source fragmentation in ip6-rewrite only
   * when set-df is off (same mechanism as the ipip v6 fixups). With set-df
   * also clear a flag inherited from the frame, e.g. one VPP sent through
   * a BVI, since the rewrite's hop limit assumes ip6-rewrite decrements. */
  if (pointer_to_uword (data))
    b0->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
  else
    b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  /* Payload is the 2 byte EtherIP header plus the frame (OpenBSD's
   * ip6_plen omits the EtherIP header) */
  ip0->payload_length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) - sizeof (*ip0));
}

void
etherip_update_adj (const etherip_tunnel_t *t)
{
  adj_nbr_midchain_update_rewrite (t->l2_adj_index,
				   (etherip_tunnel_is_ip6 (t) ? etherip6_fixup : etherip4_fixup),
				   uword_to_pointer ((uword) t->set_df, void *),
				   ADJ_FLAG_MIDCHAIN_IP_STACK, etherip_build_rewrite (t));

  etherip_tunnel_stack (t);
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  ETHERIP_ENCAP_NEXT_L2_MIDCHAIN,
  ETHERIP_ENCAP_NEXT_DROP,
  ETHERIP_ENCAP_N_NEXT,
} etherip_encap_next_t;

static char *etherip_error_strings[] = {
#define etherip_error(n, s) s,
#include "error.def"
#undef etherip_error
};

/**
 * @brief TX function. Steers the frames to the tunnel's L2 midchain
 * adjacency which applies the outer header.
 */
VLIB_NODE_FN (etherip_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  vlib_combined_counter_main_t *tx_counter =
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX;
  clib_thread_index_t thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  const etherip_tunnel_t *t = NULL;
  adj_index_t adj_index = ADJ_INDEX_INVALID;
  u32 sw_if_index = ~0;
  u8 is_up = 0;
  u32 *from, n_left_from;
  u32 n_encap = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from > 0)
    {
      u32 len0;

      if (PREDICT_TRUE (n_left_from > 2))
	vlib_prefetch_buffer_header (b[2], LOAD);

      if (PREDICT_FALSE (sw_if_index != vnet_buffer (b[0])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
	  t = pool_elt_at_index (em->tunnels, hi->dev_instance);
	  adj_index = t->l2_adj_index;
	  is_up = vnet_sw_interface_is_admin_up (vnm, t->sw_if_index);
	}

      len0 = vlib_buffer_length_in_chain (vm, b[0]);

      if (PREDICT_TRUE (is_up))
	{
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = adj_index;
	  next[0] = ETHERIP_ENCAP_NEXT_L2_MIDCHAIN;

	  /* GRE TEB does not count TX; count the frame as VXLAN does */
	  vlib_increment_combined_counter (tx_counter, thread_index, sw_if_index, 1, len0);
	  n_encap++;
	}
      else
	{
	  /* the unstacked adjacency would drop it; drop it here, uncounted
	   * as TX/ENCAP */
	  next[0] = ETHERIP_ENCAP_NEXT_DROP;
	  b[0]->error = node->errors[ETHERIP_ERROR_TX_DOWN];
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  etherip_tx_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->tunnel_sw_if_index = t->sw_if_index;
	  tr->src = t->tunnel_src;
	  tr->dst = t->tunnel_dst.fp_addr;
	  tr->length = len0;
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index, ETHERIP_ERROR_ENCAP, n_encap);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (etherip_encap_node) = {
  .name = "etherip-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_etherip_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ETHERIP_N_ERROR,
  .error_strings = etherip_error_strings,
  .n_next_nodes = ETHERIP_ENCAP_N_NEXT,
  .next_nodes = {
    [ETHERIP_ENCAP_NEXT_L2_MIDCHAIN] = "adj-l2-midchain",
    [ETHERIP_ENCAP_NEXT_DROP] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_etherip_tunnel_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  etherip_main_t *em = &etherip_main;
  etherip_tunnel_t *t;

  if (dev_instance >= vec_len (em->tunnels))
    return format (s, "<improperly-referenced>");

  t = pool_elt_at_index (em->tunnels, dev_instance);
  return format (s, "etherip%d", t->user_instance);
}

static u8 *
format_etherip_device (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "EtherIP tunnel: id %d\n", dev_instance);
  return s;
}

VNET_DEVICE_CLASS (etherip_device_class) = {
  .name = "EtherIP tunnel device",
  .format_device_name = format_etherip_tunnel_name,
  .format_device = format_etherip_device,
  .format_tx_trace = format_etherip_tx_trace,
  .admin_up_down_function = etherip_interface_admin_up_down,
};

static clib_error_t *
etherip_init (vlib_main_t *vm)
{
  etherip_main_t *em = &etherip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 seed, i;

  clib_memset (em, 0, sizeof (em[0]));
  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  em->tunnel_by_key = hash_create_mem (0, sizeof (etherip_tunnel_key_t), sizeof (uword));

  /* each thread starts its IPv4 ID sequence at a random value */
  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);
  seed = (u32) (vlib_time_now (vm) * 1e6);
  vec_foreach_index (i, em->per_thread_data)
    em->per_thread_data[i].ip4_id = random_u32 (&seed);

  /* Refuse received EtherIP until explicitly allowed
   * (OpenBSD net.inet.etherip.allow=0) */
  em->allow = false;

  return 0;
}

VLIB_INIT_FUNCTION (etherip_init);
#endif /* CLIB_MARCH_VARIANT */
