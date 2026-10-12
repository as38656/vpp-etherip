/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/* node.c: EtherIP packet processing */

#include <vlib/vlib.h>
#include <vnet/ethernet/packet.h>
#include <etherip/etherip.h>

#define foreach_etherip_input_next                                                                 \
  _ (DROP, "error-drop")                                                                           \
  _ (ETHERNET_INPUT, "ethernet-input")

typedef enum
{
#define _(s, n) ETHERIP_INPUT_NEXT_##s,
  foreach_etherip_input_next
#undef _
    ETHERIP_INPUT_N_NEXT,
} etherip_input_next_t;

typedef struct
{
  /* tunnel sw_if_index, ~0 when no tunnel was looked up or found */
  u32 tunnel_sw_if_index;
  u32 length;
  u16 header;
  u8 is_ip6;
  ip46_address_t src;
  ip46_address_t dst;
} etherip_rx_trace_t;

extern u8 *format_etherip_rx_trace (u8 *s, va_list *args);

#ifndef CLIB_MARCH_VARIANT
u8 *
format_etherip_rx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  etherip_rx_trace_t *t = va_arg (*args, etherip_rx_trace_t *);
  ip46_type_t itype = t->is_ip6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  s = format (s, "EtherIP: tunnel %U len %d header 0x%04x src %U dst %U",
	      format_etherip_trace_tunnel, t->tunnel_sw_if_index, t->length, t->header,
	      format_ip46_address, &t->src, itype, format_ip46_address, &t->dst, itype);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

always_inline void
etherip_rx_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u32 tun_sw_if_index,
		  i32 payload_len, u16 header, const ip6_header_t *ip6, const ip4_header_t *ip4,
		  int is_ip6)
{
  etherip_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

  tr->tunnel_sw_if_index = tun_sw_if_index;
  tr->length = payload_len;
  tr->header = header;
  tr->is_ip6 = is_ip6;
  if (is_ip6)
    {
      tr->src.ip6.as_u64[0] = ip6->src_address.as_u64[0];
      tr->src.ip6.as_u64[1] = ip6->src_address.as_u64[1];
      tr->dst.ip6.as_u64[0] = ip6->dst_address.as_u64[0];
      tr->dst.ip6.as_u64[1] = ip6->dst_address.as_u64[1];
    }
  else
    {
      ip46_address_set_ip4 (&tr->src, &ip4->src_address);
      ip46_address_set_ip4 (&tr->dst, &ip4->dst_address);
    }
}

always_inline uword
etherip_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, const int is_ip6)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  vlib_combined_counter_main_t *rx_counter =
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  clib_thread_index_t thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  const i32 min_payload_len = sizeof (etherip_header_t) + sizeof (ethernet_header_t);
  const bool allow = em->allow;
  etherip_tunnel_key_t key, cached_key;
  u32 cached_tun_sw_if_index = ~0;
  u8 cached_tun_is_up = 0;
  u32 *from, n_left_from;
  u32 n_decap = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  /* no valid key is all ones (is_ip6 is 0 or 1) */
  clib_memset (&cached_key, 0xff, sizeof (cached_key));

  while (n_left_from > 0)
    {
      const ip6_header_t *ip6 = NULL;
      const ip4_header_t *ip4 = NULL;
      const etherip_header_t *eip;
      u32 tun_sw_if_index = ~0;
      i32 outer_hdr_len, payload_len, avail_len;
      u32 frame_len;
      u16 header = 0;
      u8 error;

      if (PREDICT_TRUE (n_left_from > 2))
	{
	  vlib_prefetch_buffer_header (b[2], STORE);
	  vlib_prefetch_buffer_data (b[1], LOAD);
	}

      next[0] = ETHERIP_INPUT_NEXT_DROP;

      /* ip[46]_local hands us the ip header, not the EtherIP header */
      if (is_ip6)
	{
	  ip6 = vlib_buffer_get_current (b[0]);
	  outer_hdr_len = sizeof (*ip6);
	  payload_len = clib_net_to_host_u16 (ip6->payload_length);
	}
      else
	{
	  ip4 = vlib_buffer_get_current (b[0]);
	  outer_hdr_len = ip4_header_bytes (ip4);
	  payload_len = (i32) clib_net_to_host_u16 (ip4->length) - outer_hdr_len;
	}
      avail_len = (i32) vlib_buffer_length_in_chain (vm, b[0]) - outer_hdr_len;

      /* 0. receive policy, before any other check (OpenBSD etherip_input) */
      if (PREDICT_FALSE (!allow))
	{
	  error = ETHERIP_ERROR_POLICY_DROP;
	  goto trace;
	}

      /* 1. EtherIP header plus an Ethernet header, carried in the IP payload
       * and present in the first buffer */
      if (PREDICT_FALSE (payload_len < min_payload_len || payload_len > avail_len ||
			 b[0]->current_length < outer_hdr_len + min_payload_len))
	{
	  error = ETHERIP_ERROR_TOO_SHORT;
	  goto trace;
	}

      /* 2. discard unless version is 3 and reserved bits are 0 (RFC 3378 §4) */
      eip =
	(const etherip_header_t *) ((const u8 *) vlib_buffer_get_current (b[0]) + outer_hdr_len);
      header = clib_net_to_host_u16 (eip->ver_res);
      if (PREDICT_FALSE (header != ETHERIP_HEADER_VALUE))
	{
	  error = ETHERIP_ERROR_BAD_HEADER;
	  goto trace;
	}

      /* 3. tunnel lookup, local = outer dst, remote = outer src */
      if (is_ip6)
	etherip_mk_key6 (&ip6->dst_address, &ip6->src_address, vnet_buffer (b[0])->ip.fib_index,
			 &key);
      else
	etherip_mk_key4 (&ip4->dst_address, &ip4->src_address, vnet_buffer (b[0])->ip.fib_index,
			 &key);

      if (PREDICT_FALSE (!etherip_key_is_equal (&key, &cached_key)))
	{
	  const etherip_tunnel_t *t;
	  uword *p;

	  cached_key = key;
	  p = hash_get_mem (em->tunnel_by_key, &key);
	  if (p)
	    {
	      t = pool_elt_at_index (em->tunnels, p[0]);
	      cached_tun_sw_if_index = t->sw_if_index;
	      cached_tun_is_up = vnet_sw_interface_is_admin_up (vnm, t->sw_if_index);
	    }
	  else
	    cached_tun_sw_if_index = ~0;
	}

      if (PREDICT_FALSE (~0 == cached_tun_sw_if_index))
	{
	  error = ETHERIP_ERROR_NO_SUCH_TUNNEL;
	  goto trace;
	}
      tun_sw_if_index = cached_tun_sw_if_index;

      /* 4. admin down tunnel */
      if (PREDICT_FALSE (!cached_tun_is_up))
	{
	  error = ETHERIP_ERROR_TUNNEL_DOWN;
	  goto trace;
	}

      /* 5. decapsulate */
      vlib_buffer_advance (b[0], outer_hdr_len + sizeof (etherip_header_t));
      frame_len = payload_len - sizeof (etherip_header_t);

      /* ip[46]-input leaves link layer padding after the IP payload in the
       * buffer; deliver the frame exactly as encapsulated */
      if (!(b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) && b[0]->current_length > frame_len)
	b[0]->current_length = frame_len;

      /* the outer packet's L4 checksum status does not describe the frame */
      b[0]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = tun_sw_if_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = (u32) ~0;

      vlib_increment_combined_counter (rx_counter, thread_index, tun_sw_if_index, 1 /* packets */,
				       vlib_buffer_length_in_chain (vm, b[0]) /* bytes */);

      next[0] = ETHERIP_INPUT_NEXT_ETHERNET_INPUT;
      error = ETHERIP_ERROR_NONE;
      n_decap++;

    trace:
      b[0]->error = node->errors[error];

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	etherip_rx_trace (vm, node, b[0], tun_sw_if_index, payload_len, header, ip6, ip4, is_ip6);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  /* count the packets actually decapsulated, not what is left of the frame */
  vlib_node_increment_counter (vm, node->node_index, ETHERIP_ERROR_DECAP, n_decap);

  return frame->n_vectors;
}

VLIB_NODE_FN (etherip4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return etherip_input (vm, node, from_frame, /* is_ip6 */ 0);
}

VLIB_NODE_FN (etherip6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return etherip_input (vm, node, from_frame, /* is_ip6 */ 1);
}

static char *etherip_error_strings[] = {
#define etherip_error(n, s) s,
#include "error.def"
#undef etherip_error
};

VLIB_REGISTER_NODE (etherip4_input_node) = {
  .name = "etherip4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = ETHERIP_N_ERROR,
  .error_strings = etherip_error_strings,

  .n_next_nodes = ETHERIP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [ETHERIP_INPUT_NEXT_##s] = n,
    foreach_etherip_input_next
#undef _
  },

  .format_trace = format_etherip_rx_trace,
};

VLIB_REGISTER_NODE (etherip6_input_node) = {
  .name = "etherip6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = ETHERIP_N_ERROR,
  .error_strings = etherip_error_strings,

  .n_next_nodes = ETHERIP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [ETHERIP_INPUT_NEXT_##s] = n,
    foreach_etherip_input_next
#undef _
  },

  .format_trace = format_etherip_rx_trace,
};
