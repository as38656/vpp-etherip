/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ryosuke Nakayama.
 */

/*
 * etherip_api.c - EtherIP api
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <etherip/etherip.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <etherip/etherip.api_enum.h>
#include <etherip/etherip.api_types.h>

#define REPLY_MSG_ID_BASE etherip_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_etherip_tunnel_add_del_t_handler (vl_api_etherip_tunnel_add_del_t *mp)
{
  vnet_etherip_tunnel_add_del_args_t _a = {}, *a = &_a;
  vl_api_etherip_tunnel_add_del_reply_t *rmp;
  u32 sw_if_index = ~0;
  ip46_type_t itype[2];
  int rv = 0;

  itype[0] = ip_address_decode (&mp->tunnel.src, &a->src);
  itype[1] = ip_address_decode (&mp->tunnel.dst, &a->dst);

  if (IP46_TYPE_ANY == itype[0] || IP46_TYPE_ANY == itype[1])
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto out;
    }

  if (itype[0] != itype[1])
    {
      rv = VNET_API_ERROR_INVALID_PROTOCOL;
      goto out;
    }

  a->is_add = mp->is_add;
  a->is_ip6 = (itype[0] == IP46_TYPE_IP6);
  a->instance = ntohl (mp->tunnel.instance);
  a->outer_table_id = ntohl (mp->tunnel.outer_table_id);
  a->hop_limit = mp->tunnel.hop_limit;
  a->dscp = ip_dscp_decode (mp->tunnel.dscp);
  a->set_df = mp->tunnel.set_df;

  rv = vnet_etherip_tunnel_add_del (a, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_ETHERIP_TUNNEL_ADD_DEL_REPLY, ({ rmp->sw_if_index = htonl (sw_if_index); }));
}

static void
send_etherip_tunnel_details (const etherip_tunnel_t *t, vl_api_etherip_tunnel_dump_t *mp)
{
  vl_api_etherip_tunnel_details_t *rmp;
  fib_protocol_t fproto = t->tunnel_dst.fp_proto;
  ip46_type_t itype = (FIB_PROTOCOL_IP6 == fproto) ? IP46_TYPE_IP6 : IP46_TYPE_IP4;

  REPLY_MACRO_DETAILS2 (VL_API_ETHERIP_TUNNEL_DETAILS, ({
			  clib_memset (&rmp->tunnel, 0, sizeof (rmp->tunnel));
			  rmp->tunnel.instance = htonl (t->user_instance);
			  ip_address_encode (&t->tunnel_src, itype, &rmp->tunnel.src);
			  ip_address_encode (&t->tunnel_dst.fp_addr, itype, &rmp->tunnel.dst);
			  rmp->tunnel.outer_table_id =
			    htonl (fib_table_get_table_id (t->outer_fib_index, fproto));
			  rmp->tunnel.sw_if_index = htonl (t->sw_if_index);
			  rmp->tunnel.hop_limit = t->hop_limit;
			  rmp->tunnel.dscp = ip_dscp_encode (t->dscp);
			  rmp->tunnel.set_df = t->set_df;
			}));
}

static void
vl_api_etherip_tunnel_dump_t_handler (vl_api_etherip_tunnel_dump_t *mp)
{
  vl_api_registration_t *reg;
  etherip_main_t *em = &etherip_main;
  etherip_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, em->tunnels)
	{
	  send_etherip_tunnel_details (t, mp);
	}
    }
  else
    {
      t = etherip_tunnel_get_by_sw_if_index (sw_if_index);
      if (NULL != t)
	send_etherip_tunnel_details (t, mp);
    }
}

static void
vl_api_etherip_set_allow_t_handler (vl_api_etherip_set_allow_t *mp)
{
  vl_api_etherip_set_allow_reply_t *rmp;
  int rv = 0;

  vnet_etherip_set_allow (mp->enable);

  REPLY_MACRO (VL_API_ETHERIP_SET_ALLOW_REPLY);
}

static void
vl_api_etherip_get_allow_t_handler (vl_api_etherip_get_allow_t *mp)
{
  vl_api_etherip_get_allow_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_ETHERIP_GET_ALLOW_REPLY, ({ rmp->enable = etherip_main.allow; }));
}

/*
 * etherip_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
/* API definitions */
#include <vnet/format_fns.h>
#include <etherip/etherip.api.c>

static clib_error_t *
etherip_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  etherip_main.msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (etherip_api_hookup);
