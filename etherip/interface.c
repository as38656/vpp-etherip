/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/* interface.c: EtherIP tunnel interfaces */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/l2/l2_input.h>
#include <vppinfra/random.h>
#include <etherip/etherip.h>

static u8 *
format_etherip_tunnel (u8 *s, va_list *args)
{
  etherip_tunnel_t *t = va_arg (*args, etherip_tunnel_t *);
  fib_protocol_t fproto = t->tunnel_dst.fp_proto;
  ip46_type_t itype = (FIB_PROTOCOL_IP6 == fproto) ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  s =
    format (s, "[%d] %U instance %d src %U dst %U outer-table-id %d sw-if-idx %d ", t->dev_instance,
	    format_vnet_sw_if_index_name, vnet_get_main (), t->sw_if_index, t->user_instance,
	    format_ip46_address, &t->tunnel_src, itype, format_ip46_address, &t->tunnel_dst.fp_addr,
	    itype, fib_table_get_table_id (t->outer_fib_index, fproto), t->sw_if_index);

  s = format (s, "hop-limit %d dscp %d set-df %s l2-adj-idx %d", t->hop_limit, t->dscp,
	      t->set_df ? "on" : "off", t->l2_adj_index);

  return s;
}

static void
etherip_mk_key_from_args (const vnet_etherip_tunnel_add_del_args_t *a, u32 outer_fib_index,
			  etherip_tunnel_key_t *key)
{
  if (a->is_ip6)
    etherip_mk_key6 (&a->src.ip6, &a->dst.ip6, outer_fib_index, key);
  else
    etherip_mk_key4 (&a->src.ip4, &a->dst.ip4, outer_fib_index, key);
}

static etherip_tunnel_t *
etherip_tunnel_db_find (const etherip_tunnel_key_t *key)
{
  etherip_main_t *em = &etherip_main;
  uword *p;

  p = hash_get_mem (em->tunnel_by_key, key);
  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (em->tunnels, p[0]));
}

static void
etherip_tunnel_db_add (const etherip_tunnel_t *t, const etherip_tunnel_key_t *key)
{
  etherip_main_t *em = &etherip_main;

  hash_set_mem_alloc (&em->tunnel_by_key, key, t->dev_instance);
}

static void
etherip_tunnel_db_remove (const etherip_tunnel_key_t *key)
{
  etherip_main_t *em = &etherip_main;

  hash_unset_mem_free (&em->tunnel_by_key, key);
}

/**
 * etherip_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's L2 midchain adjacency.
 * The tunnel has only this one midchain, so there is no adjacency walk.
 */
void
etherip_tunnel_stack (const etherip_tunnel_t *t)
{
  if (ADJ_INDEX_INVALID == t->l2_adj_index)
    return;

  if ((vnet_hw_interface_get_flags (vnet_get_main (), t->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    {
      adj_midchain_delegate_unstack (t->l2_adj_index);
    }
  else
    {
      adj_midchain_delegate_stack (t->l2_adj_index, t->outer_fib_index, &t->tunnel_dst);
    }
}

/*
 * adj-l2-midchain continues on the ethernet-output arc, so only that arc
 * ends at tunnel-output-no-count. The ip4/ip6/mpls output arcs keep
 * interface-output: their adjacencies on this interface are not midchains
 * (GRE TEB changes all four arcs, gre/interface.c:508).
 */
static void
etherip_set_ethernet_output_end_node (u32 sw_if_index, char *node_name)
{
  vlib_node_t *n;

  n = vlib_get_node_by_name (etherip_main.vlib_main, (u8 *) node_name);
  vnet_feature_modify_end_node (ethernet_main.output_feature_arc_index, sw_if_index, n->index);
}

/*
 * Return the interfaces cross-connected to the tunnel to L3, so that none
 * keeps forwarding to the deleted (and possibly reused) sw_if_index. GRE
 * and VXLAN leave them in place.
 */
static void
etherip_xconnect_peers_to_l3 (u32 sw_if_index)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  l2_input_config_t *config;
  u32 i;

  vec_foreach_index (i, l2input_main.configs)
    {
      config = vec_elt_at_index (l2input_main.configs, i);
      if (i == sw_if_index || !l2_input_is_xconnect (config) ||
	  config->output_sw_if_index != sw_if_index || !vnet_sw_interface_is_valid (vnm, i))
	continue;

      set_int_l2_mode (em->vlib_main, vnm, MODE_L3, i, 0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
    }
}

static int
vnet_etherip_tunnel_add (const vnet_etherip_tunnel_add_del_args_t *a, u32 outer_fib_index,
			 u32 *sw_if_indexp)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  vnet_eth_interface_registration_t eir = {};
  etherip_tunnel_key_t key;
  vnet_hw_interface_t *hi;
  etherip_tunnel_t *t;
  u32 hw_if_index, sw_if_index, t_idx, u_idx;
  u8 address[6];
  u32 rnd;

  etherip_mk_key_from_args (a, outer_fib_index, &key);
  if (NULL != etherip_tunnel_db_find (&key))
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  /* Reconcile the real dev_instance and a possible requested instance.
   * Without a request, take the lowest instance number not in use. */
  if (~0 == a->instance)
    {
      for (u_idx = 0; hash_get (em->instance_used, u_idx); u_idx++)
	;
    }
  else
    {
      u_idx = a->instance;
      if (hash_get (em->instance_used, u_idx))
	return VNET_API_ERROR_INSTANCE_IN_USE;
    }

  pool_get_aligned (em->tunnels, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  t_idx = t - em->tunnels;
  hash_set (em->instance_used, u_idx, 1);

  t->dev_instance = t_idx;  /* actual */
  t->user_instance = u_idx; /* name */
  t->hop_limit = a->hop_limit ? a->hop_limit : ETHERIP_DEFAULT_HOP_LIMIT;
  t->dscp = a->dscp;
  t->set_df = a->set_df;
  t->outer_fib_index = outer_fib_index;
  t->l2_adj_index = ADJ_INDEX_INVALID;

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  t->tunnel_dst.fp_len = !a->is_ip6 ? 32 : 128;
  t->tunnel_dst.fp_proto = !a->is_ip6 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  t->tunnel_dst.fp_addr = a->dst;

  /* locally administered MAC address, as VXLAN: 02:fe + 4 random bytes */
  rnd = (u32) (vlib_time_now (em->vlib_main) * 1e6);
  rnd = random_u32 (&rnd);
  address[0] = 0x02;
  address[1] = 0xfe;
  clib_memcpy (address + 2, &rnd, sizeof (rnd));

  eir.dev_class_index = etherip_device_class.index;
  eir.dev_instance = t_idx;
  eir.address = address;
  hw_if_index = vnet_eth_register_interface (vnm, &eir);

  /* frames sent on the interface go to the encap node */
  vnet_set_interface_output_node (vnm, hw_if_index, etherip_encap_node.index);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;

  t->hw_if_index = hw_if_index;
  t->sw_if_index = sw_if_index;

  vec_validate_init_empty (em->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  em->tunnel_index_by_sw_if_index[sw_if_index] = t_idx;

  if (!a->is_ip6)
    hi->frame_overhead = sizeof (etherip_header_t) + sizeof (ip4_header_t);
  else
    hi->frame_overhead = sizeof (etherip_header_t) + sizeof (ip6_header_t);
  hi->min_frame_size = hi->frame_overhead + 64;

  /* Standard default MTU, as GRE TEB. */
  vnet_sw_interface_set_mtu (vnm, sw_if_index, 9000);

  etherip_tunnel_db_add (t, &key);

  /*
   * All frames use one L2 midchain. Set the end of the ethernet-output
   * arc before the adjacency picks up its next node from it.
   */
  t->l2_adj_index =
    adj_nbr_add_or_lock (t->tunnel_dst.fp_proto, VNET_LINK_ETHERNET, &zero_addr, sw_if_index);
  etherip_set_ethernet_output_end_node (sw_if_index, "tunnel-output-no-count");
  etherip_update_adj (t);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  if (a->is_ip6 && !em->ip6_protocol_registered)
    {
      ip6_register_protocol (IP_PROTOCOL_ETHERIP, etherip6_input_node.index);
      em->ip6_protocol_registered = true;
    }
  else if (!a->is_ip6 && !em->ip4_protocol_registered)
    {
      ip4_register_protocol (IP_PROTOCOL_ETHERIP, etherip4_input_node.index);
      em->ip4_protocol_registered = true;
    }

  return 0;
}

static int
vnet_etherip_tunnel_del (const vnet_etherip_tunnel_add_del_args_t *a, u32 outer_fib_index,
			 u32 *sw_if_indexp)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  etherip_tunnel_key_t key;
  etherip_tunnel_t *t;
  u32 sw_if_index;

  etherip_mk_key_from_args (a, outer_fib_index, &key);
  t = etherip_tunnel_db_find (&key);
  if (NULL == t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */);

  /* make sure tunnel is removed from l2 bd or xconnect; leaving the bd
   * also flushes the MACs learned on it and drops L2 output to it */
  etherip_xconnect_peers_to_l3 (sw_if_index);
  set_int_l2_mode (em->vlib_main, vnm, MODE_L3, sw_if_index, 0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
  em->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

  ethernet_delete_interface (vnm, t->hw_if_index);

  if (t->l2_adj_index != ADJ_INDEX_INVALID)
    {
      adj_midchain_delegate_unstack (t->l2_adj_index);
      adj_unlock (t->l2_adj_index);
    }

  etherip_set_ethernet_output_end_node (sw_if_index, "interface-output");
  hash_unset (em->instance_used, t->user_instance);
  etherip_tunnel_db_remove (&key);
  pool_put (em->tunnels, t);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

static int
etherip_address_is_multicast (const ip46_address_t *addr, u8 is_ip6)
{
  return (is_ip6 ? ip6_address_is_multicast (&addr->ip6) : ip4_address_is_multicast (&addr->ip4));
}

int
vnet_etherip_tunnel_add_del (const vnet_etherip_tunnel_add_del_args_t *a, u32 *sw_if_indexp)
{
  u32 outer_fib_index;

  if (ip46_address_is_zero (&a->src))
    return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  if (ip46_address_is_zero (&a->dst))
    return VNET_API_ERROR_INVALID_DST_ADDRESS;

  if (ip46_address_is_equal (&a->src, &a->dst))
    return VNET_API_ERROR_SAME_SRC_DST;

  outer_fib_index =
    fib_table_find ((a->is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4), a->outer_table_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (!a->is_add)
    return (vnet_etherip_tunnel_del (a, outer_fib_index, sw_if_indexp));

  /* point-to-point only: no multicast endpoints, as OpenBSD
   * etherip_set_tunnel */
  if (etherip_address_is_multicast (&a->src, a->is_ip6))
    return VNET_API_ERROR_INVALID_SRC_ADDRESS;

  if (etherip_address_is_multicast (&a->dst, a->is_ip6))
    return VNET_API_ERROR_INVALID_DST_ADDRESS;

  /* 6 bit DSCP; the ECN bits are never set */
  if (a->dscp > 63)
    return VNET_API_ERROR_INVALID_VALUE;

  return (vnet_etherip_tunnel_add (a, outer_fib_index, sw_if_indexp));
}

void
vnet_etherip_set_allow (bool enable)
{
  etherip_main.allow = enable;
}

clib_error_t *
etherip_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  etherip_tunnel_t *t;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  t = etherip_tunnel_get_by_sw_if_index (hi->sw_if_index);
  if (NULL == t)
    /* not one of ours */
    return (NULL);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */);

  etherip_tunnel_stack (t);

  return /* no error */ 0;
}

static clib_error_t *
create_etherip_tunnel_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_etherip_tunnel_add_del_args_t _a, *a = &_a;
  ip46_address_t src = ip46_address_initializer, dst = ip46_address_initializer;
  u32 instance = ~0;
  u32 outer_table_id = 0;
  u32 hop_limit = 0;
  u32 dscp = 0;
  ip_dscp_t dscp_name;
  u8 set_df = 0;
  u8 is_add = 1;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "instance %u", &instance))
	;
      else if (unformat (line_input, "src %U", unformat_ip46_address, &src, IP46_TYPE_ANY))
	;
      else if (unformat (line_input, "dst %U", unformat_ip46_address, &dst, IP46_TYPE_ANY))
	;
      else if (unformat (line_input, "outer-table-id %u", &outer_table_id))
	;
      else if (unformat (line_input, "hop-limit %u", &hop_limit))
	;
      else if (unformat (line_input, "dscp %U", unformat_ip_dscp, &dscp_name))
	dscp = dscp_name;
      else if (unformat (line_input, "dscp %u", &dscp))
	;
      else if (unformat (line_input, "set-df"))
	set_df = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (ip46_address_is_zero (&src))
    {
      error = clib_error_return (0, "source address not specified");
      goto done;
    }

  if (ip46_address_is_zero (&dst))
    {
      error = clib_error_return (0, "destination address not specified");
      goto done;
    }

  if (ip46_address_is_ip4 (&src) != ip46_address_is_ip4 (&dst))
    {
      error = clib_error_return (0, "src and dst address must be the same AF");
      goto done;
    }

  if (hop_limit > 255)
    {
      error = clib_error_return (0, "hop-limit %u out of range (1-255)", hop_limit);
      goto done;
    }

  if (dscp > 63)
    {
      error = clib_error_return (0, "dscp %u out of range (0-63)", dscp);
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->is_ip6 = !ip46_address_is_ip4 (&src);
  a->instance = instance;
  a->outer_table_id = outer_table_id;
  a->hop_limit = hop_limit;
  a->dscp = dscp;
  a->set_df = set_df;
  clib_memcpy (&a->src, &src, sizeof (a->src));
  clib_memcpy (&a->dst, &dst, sizeof (a->dst));

  rv = vnet_etherip_tunnel_add_del (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      error = clib_error_return (0, "EtherIP tunnel already exists");
      break;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "outer table ID %u doesn't exist", outer_table_id);
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "EtherIP tunnel doesn't exist");
      break;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Instance is in use");
      break;
    case VNET_API_ERROR_SAME_SRC_DST:
      error = clib_error_return (0, "src and dst are identical");
      break;
    case VNET_API_ERROR_INVALID_SRC_ADDRESS:
      error = clib_error_return (0, "invalid src address (multicast)");
      break;
    case VNET_API_ERROR_INVALID_DST_ADDRESS:
      error = clib_error_return (0, "invalid dst address (multicast)");
      break;
    default:
      error = clib_error_return (0, "vnet_etherip_tunnel_add_del returned %d (%U)", rv,
				 format_vnet_api_errno, rv);
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (create_etherip_tunnel_command, static) = {
  .path = "create etherip tunnel",
  .short_help = "create etherip tunnel src <addr> dst <addr> [instance <n>] "
		"[outer-table-id <id>] [hop-limit <1-255>] [dscp <dscp>] [set-df] [del]",
  .function = create_etherip_tunnel_command_fn,
};

static clib_error_t *
show_etherip_tunnel_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  etherip_main_t *em = &etherip_main;
  vnet_main_t *vnm = em->vnet_main;
  etherip_tunnel_t *t;
  u32 sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (~0 != sw_if_index)
    {
      t = etherip_tunnel_get_by_sw_if_index (sw_if_index);
      if (NULL == t)
	return clib_error_return (0, "%U is not an EtherIP tunnel", format_vnet_sw_if_index_name,
				  vnm, sw_if_index);

      vlib_cli_output (vm, "%U", format_etherip_tunnel, t);
      return 0;
    }

  if (pool_elts (em->tunnels) == 0)
    vlib_cli_output (vm, "No EtherIP tunnels configured...");

  pool_foreach (t, em->tunnels)
    {
      vlib_cli_output (vm, "%U", format_etherip_tunnel, t);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_etherip_tunnel_command, static) = {
  .path = "show etherip tunnel",
  .short_help = "show etherip tunnel [<interface>]",
  .function = show_etherip_tunnel_command_fn,
};

static clib_error_t *
set_etherip_allow_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  int enable = -1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected on or off");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	enable = 1;
      else if (unformat (line_input, "off"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (enable < 0)
    {
      error = clib_error_return (0, "expected on or off");
      goto done;
    }

  vnet_etherip_set_allow (enable);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (set_etherip_allow_command, static) = {
  .path = "set etherip allow",
  .short_help = "set etherip allow (on|off)",
  .function = set_etherip_allow_command_fn,
};

static clib_error_t *
show_etherip_allow_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "allow: %s", etherip_main.allow ? "on" : "off");

  return 0;
}

VLIB_CLI_COMMAND (show_etherip_allow_command, static) = {
  .path = "show etherip allow",
  .short_help = "show etherip allow",
  .function = show_etherip_allow_command_fn,
};
