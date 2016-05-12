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
#ifndef __included_ctrlcap_h__
#define __included_ctrlcap_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>
/*
   From draft-ietf-sfc-nsh: Network Service Header Format

   A NSH is composed of a 4-byte Base Header, a 4-byte Service Path
   Header and Context Headers, as shown in Figure 1 below.


    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Base Header                                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Service Path Header                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                Context Headers                                ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 1: Network Service Header

   Base header: provides information about the service header and the
   payload protocol.

   Service Path Header: provide path identification and location within
   a path.

   Context headers: carry opaque metadata and variable length encoded
   information.


   NSH Base Header

      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Ver|O|C|R|R|R|R|R|R|   Length  |    MD Type    | Next Protocol |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Service Path Header

      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Service Path ID                      | Service Index |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Service path ID (SPI): 24 bits
   Service index (SI): 8 bits

*/

typedef struct {
    /* base header */
    u8 flags;    // VVOCRRRR - should be 0x0 for our case
    u8 rr_len;   // RRLLLLLL - should be 0x2 for our case
    u8 md_type;  // should be 0x2 (no context headers)
    u8 next_proto; // 0x1 - ipv4, 0x2 - ipv6, 0x3 - ethernet
    /* service path header */
    u32 sph;    // used as 32bit number (global if index)
} nsh_header_t;

typedef CLIB_PACKED (struct {
    ip4_header_t ip4;            /* 20 bytes */
    udp_header_t udp;            /* 8 bytes */
    nsh_header_t nsh;        /* 8 bytes */
}) ip4_nsh_header_t;

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;

    /* is the plugin configured and enabled */
    u8 is_enabled;

    /* NSH encaped pkts source and destination */
    ip4_address_t src_addr;
    u16 src_port;
    ip4_address_t dst_addr;
    u16 dst_port;

    /* pre-prepared ip4 udp nsh header */
    ip4_nsh_header_t ip4_nsh_hdr;
} ctrlcap_main_t;

ctrlcap_main_t ctrlcap_main;

vlib_node_registration_t ctrlcap_punt_node;

#endif /* __included_ctrlcap_h__ */
