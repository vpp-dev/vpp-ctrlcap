/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 *------------------------------------------------------------------
 * ctrlcap.c - simple MAC-swap API / debug CLI handling
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ctrlcap/ctrlcap.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <ctrlcap/ctrlcap_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ctrlcap/ctrlcap_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ctrlcap/ctrlcap_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ctrlcap/ctrlcap_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ctrlcap/ctrlcap_all_api_h.h>
#undef vl_api_version

/* 
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+cm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);


/* List of message types that this plugin understands */

#define foreach_ctrlcap_plugin_api_msg                           \
_(CTRLCAP_ENABLE_DISABLE, ctrlcap_enable_disable)                \
_(CTRLCAP_SET, ctrlcap_set)

// Prepare ip4 + udp + nsh header
static int ip4_nsh_header_prep(ip4_nsh_header_t *hdr,
        ip4_address_t *src, u16 src_port,
        ip4_address_t *dst, u16 dst_port)
{
    ip4_header_t *ip = &hdr->ip4;
    ip->ip_version_and_header_length = 0x45;
    ip->ttl = 254;
    ip->protocol = IP_PROTOCOL_UDP;
    ip->src_address.as_u32 = src->as_u32;
    ip->dst_address.as_u32 = dst->as_u32;
    ip->checksum = ip4_header_checksum(ip);

    hdr->udp.src_port = clib_host_to_net_u16 (src_port);
    hdr->udp.dst_port = clib_host_to_net_u16 (dst_port);

    hdr->nsh.flags = 0x0;
    hdr->nsh.rr_len = 0x2;
    hdr->nsh.md_type = 0x2;
    hdr->nsh.next_proto = 0x2;

    hdr->nsh.sph = 0x0;
    return 0;
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 * result = va_arg (*args, u8 *);
  unsigned a[4];

  if (! unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */

clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  ctrlcap_main_t * cm = &ctrlcap_main;
  clib_error_t * error = 0;

  cm->vlib_main = vm;
  cm->vnet_main = h->vnet_main;
  cm->ethernet_main = h->ethernet_main;

  return error;
}

/* Action function shared between message handler and debug CLI */
int ctrlcap_enable_disable (ctrlcap_main_t * cm, 
                            ip4_address_t *src, u16 src_port,
                            ip4_address_t *dst, u16 dst_port,
                            int enable_disable)
{
    int rv = 0;

    if (!enable_disable) {
        // TODO: remove all redirects
        cm->is_enabled = 0;
        return 0;
    }

    // TODO: reapply all redirects

    memcpy(&cm->src_addr, src, sizeof(cm->src_addr));
    cm->src_port = src_port;
    memcpy(&cm->dst_addr, dst, sizeof(cm->dst_addr));
    cm->dst_port = dst_port;

    // prepare header
    rv = ip4_nsh_header_prep(&cm->ip4_nsh_hdr,
            src, src_port, dst, dst_port);

    cm->is_enabled = 1;
    return rv;
}

int ctrlcap_set (ctrlcap_main_t * cm, u32 sw_if_index,
                 u32 sw_if_gid, int enable_disable)
{
    vnet_sw_interface_t * sw;
    int rv;
    u32 node_index = enable_disable ? ctrlcap_punt_node.index : ~0;

    if (!cm->is_enabled)
        return -200; // FIXME!

    /* Utterly wrong? */
    if (pool_is_free_index (cm->vnet_main->interface_main.sw_interfaces,
                            sw_if_index))
        return VNET_API_ERROR_INVALID_SW_IF_INDEX;

    /* Not a physical port? */
    sw = vnet_get_sw_interface (cm->vnet_main, sw_if_index);
    if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
        return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    
    /* 
     * Redirect pkts from the driver to the ctrlcap node.
     * Returns VNET_API_ERROR_UNIMPLEMENTED if the h/w driver
     * doesn't implement the API. 
     *
     * Node_index = ~0 => shut off redirection
     */
    rv = vnet_hw_interface_rx_redirect_to_node (cm->vnet_main, sw_if_index,
                                                node_index);
    if (rv == 0) {
        // if everything worked update interface id maps
        if (enable_disable) {
            hash_set(cm->sw_if_index_by_gid, sw_if_gid, sw_if_index);
            hash_set(cm->gid_by_sw_if_index, sw_if_index, sw_if_gid);
        } else {
            hash_unset(cm->sw_if_index_by_gid, sw_if_gid);
            hash_unset(cm->gid_by_sw_if_index, sw_if_index);
        }
    }
    return rv;
}

static clib_error_t *
ctrlcap_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
    ctrlcap_main_t * cm = &ctrlcap_main;
    int enable_disable = 1;
    u8 src_set = 0;
    u8 dst_set = 0;
    ip4_address_t src, dst;
    u16 src_port, dst_port;
    int rv;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat(input, "src %U:%d", unformat_ip4_address, &src, &src_port))
          src_set = 1;
      else if (unformat(input, "dst %U:%d", unformat_ip4_address, &dst, &dst_port))
          dst_set = 1;
      else
        break;
    }

    if (src_set == 0)
        return clib_error_return (0, "Please specify source IP and port.");
    if (dst_set == 0)
        return clib_error_return (0, "Please specify destination IP and port.");

    rv = ctrlcap_enable_disable (cm, &src, src_port, &dst, dst_port, enable_disable);

    switch(rv) {
    case 0:
        break;

    default:
        return clib_error_return (0, "ctrlcap_enable_disable returned %d",
                                  rv);
    }
    return 0;
}

VLIB_CLI_COMMAND (ctrlcap_enable_disable_command, static) = {
    .path = "ctrlcap config",
    .short_help = 
    "ctrlcap config src <source-ipv4>:<source port> dst <destination-ipv4>:<destination port> [disable]",
    .function = ctrlcap_enable_disable_command_fn,
};

static clib_error_t *
ctrlcap_set_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  ctrlcap_main_t * cm = &ctrlcap_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  u32 sw_if_gid = ~0;
    
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       cm->vnet_main, &sw_if_index))
      ;
    else if (unformat (input, "gid %u", &sw_if_gid))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (sw_if_gid == ~0)
      return clib_error_return (0, "Please specify interface global id (gid)...");
    
  rv = ctrlcap_set (cm, sw_if_index, sw_if_gid, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return 
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  case -200:    // FIXME!
    return clib_error_return (0, "Cannot set, ctrlcap is not enabled and "
                        "configured. Use 'ctrlcap config' CLI command.");
    break;

  default:
    return clib_error_return (0, "ctrlcap_set returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (ctrlcap_set_command, static) = {
    .path = "ctrlcap set",
    .short_help = 
    "ctrlcap set <interface-name> gid <global-iface-id> [disable]",
    .function = ctrlcap_set_command_fn,
};

/* API message handler */
static void vl_api_ctrlcap_enable_disable_t_handler
(vl_api_ctrlcap_enable_disable_t * mp)
{
    vl_api_ctrlcap_enable_disable_reply_t * rmp;
    ctrlcap_main_t * cm = &ctrlcap_main;
    int rv;
    ip4_address_t src, dst;
    src.as_u32 = ntohl (mp->src_address);
    dst.as_u32 = ntohl (mp->dst_address);

    rv = ctrlcap_enable_disable (cm,
            &src, clib_host_to_net_u16(mp->src_port),
            &dst, clib_host_to_net_u16(mp->dst_port),
            (int) (mp->enable_disable));

    REPLY_MACRO(VL_API_CTRLCAP_ENABLE_DISABLE_REPLY);
}

static void vl_api_ctrlcap_set_t_handler
(vl_api_ctrlcap_set_t * mp)
{
  vl_api_ctrlcap_set_reply_t * rmp;
  ctrlcap_main_t * cm = &ctrlcap_main;
  int rv;

  rv = ctrlcap_set (cm, ntohl(mp->sw_if_index), 
          ntohl(mp->sw_if_gid), (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_CTRLCAP_SET_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
ctrlcap_plugin_api_hookup (vlib_main_t *vm)
{
  ctrlcap_main_t * cm = &ctrlcap_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + cm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_ctrlcap_plugin_api_msg;
#undef _

    return 0;
}

static clib_error_t * ctrlcap_init (vlib_main_t * vm)
{
  ctrlcap_main_t * cm = &ctrlcap_main;
  clib_error_t * error = 0;
  u8 * name;

  name = format (0, "ctrlcap_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  cm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = ctrlcap_plugin_api_hookup (vm);

  cm->sw_if_index_by_gid = hash_create(0, sizeof (u32));
  cm->gid_by_sw_if_index = hash_create(0, sizeof (u32));

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (ctrlcap_init);


