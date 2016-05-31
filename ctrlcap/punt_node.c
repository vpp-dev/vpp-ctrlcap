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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ctrlcap/ctrlcap.h>

typedef struct {
    u32 next_index;
    u32 sw_if_index;
    u32 gid;
} ctrlcap_punt_trace_t;

/* packet trace format function */
static u8 * format_ctrlcap_punt_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ctrlcap_punt_trace_t * t = va_arg (*args, ctrlcap_punt_trace_t *);

    s = format (s, "ctrlcap punt: rx sw_if_index %d, next index %d, gid %d",
                t->sw_if_index, t->next_index, t->gid);
    return s;
}

vlib_node_registration_t ctrlcap_punt_node;

#define foreach_ctrlcap_error \
_(PUNTED, "Control packets punted") \
_(INVALID, "Packets invalid")

typedef enum {
#define _(sym,str) CTRLCAP_ERROR_##sym,
    foreach_ctrlcap_error
#undef _
    CTRLCAP_N_ERROR,
} ctrlcap_error_t;

static char * ctrlcap_error_strings[] = {
#define _(sym,string) string,
    foreach_ctrlcap_error
#undef _
};

typedef enum {
    CTRLCAP_PUNT_NEXT_IP4_LOOKUP,
    CTRLCAP_PUNT_NEXT_ETHERNET_INPUT,
    CTRLCAP_PUNT_NEXT_ERROR_DROP,
    CTRLCAP_N_NEXT,
} ctrlcap_next_t;

#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

#define foreach_fixed_header4_offset            \
    _(0) _(1) _(2) _(3)

u8 should_encap(ethernet_header_t *en)
{
    // arp
    if (PREDICT_FALSE(en->type == 0x0806))
        return 1;

    // ipv4
    if (en->type != 0x0800)
        return 0;

    ip4_header_t *ip = (ip4_header_t *)(en+1);
    if (PREDICT_FALSE(
               ip->protocol == 0x09  // IGP
            || ip->protocol == 0x59  // OSPF
            || ip->protocol == 0x7C)) // IS-IS over IPv4
        return 1;

    // TCP
    if (ip->protocol != 0x06)
        return 0;

    tcp_header_t *tcp = (tcp_header_t *)(ip+1);
    // BGP ports
    if (PREDICT_TRUE(clib_net_to_host_u16(tcp->ports.src) != 179
            && clib_net_to_host_u16(tcp->ports.dst) != 179))
        return 0;

    return 1;
}

static uword
ctrlcap_punt_node_fn (vlib_main_t * vm,
          vlib_node_runtime_t * node,
          vlib_frame_t * frame)
{
    ctrlcap_main_t *cm = &ctrlcap_main;
    u32 n_left_from, * from, * to_next;
    ctrlcap_next_t next_index;
    u32 pkts_punted = 0;
    u32 pkts_invalid = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                 to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next >= 2)
        {
            u32 next0 = CTRLCAP_PUNT_NEXT_IP4_LOOKUP; //CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            u32 next1 = CTRLCAP_PUNT_NEXT_IP4_LOOKUP; //CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            u32 sw_if_index0, sw_if_index1;
            u32 bi0, bi1;
            vlib_buffer_t * b0, * b1;
            udp_header_t * udp0, * udp1;
            u16 old_l0 = 0, old_l1 = 0;
            u16 new_l0, new_l1;
            ip_csum_t sum0, sum1;
            u32 gid0 = ~0;
            u32 gid1 = ~0;
          
            /* Prefetch next iteration. */
            {
                vlib_buffer_t * p2, * p3;
                  
                p2 = vlib_get_buffer (vm, from[2]);
                p3 = vlib_get_buffer (vm, from[3]);
                  
                vlib_prefetch_buffer_header (p2, LOAD);
                vlib_prefetch_buffer_header (p3, LOAD);

                CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
                CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
            }

            /* speculatively enqueue b0 and b1 to the current next frame */
            to_next[0] = bi0 = from[0];
            to_next[1] = bi1 = from[1];
            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);

            ASSERT (b0->current_data == 0);
            ASSERT (b1->current_data == 0);

            ethernet_header_t *en0 = vlib_buffer_get_current (b0);
            ethernet_header_t *en1 = vlib_buffer_get_current (b1);

            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

            if (PREDICT_TRUE(!should_encap(en0))) {
                next0 = CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            } else {
                uword *p = 0;
                p = hash_get (cm->gid_by_sw_if_index, sw_if_index0);
                if (PREDICT_FALSE(p == 0)) {
                    next0 = CTRLCAP_PUNT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    gid0 = p[0];
                    // set global interface id
                    cm->ip4_nsh_hdr.nsh.sph = gid0;

                    vlib_buffer_advance (b0, -(word)sizeof(ip4_nsh_header_t));
                    ip4_header_t *ip4_0 = vlib_buffer_get_current (b0);
    // copy 8-bytes at a time
#define _(off) ((u64 *)ip4_0)[off] = ((u64 *)&cm->ip4_nsh_hdr)[off];
                    foreach_fixed_header4_offset;
#undef _

                    // last 4 bytes
                    ((u32 *)ip4_0)[8] = ((u32 *)&cm->ip4_nsh_hdr)[8];

                    /* recalculate IP checksum */
                    sum0 = ip4_0->checksum;
                    new_l0 = 
                      clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
                      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                           length /* changed member */);
                    ip4_0->checksum = ip_csum_fold (sum0);
                    ip4_0->length = new_l0;

                    /* recalculate UDP len */
                    udp0 = (udp_header_t *)(ip4_0+1);
                    new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) - sizeof (*ip4_0));
                    udp0->length = new_l0;

                    //vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0; //sw_if_index0;
                    pkts_punted += 1;
                }
            }

            if (PREDICT_TRUE(!should_encap(en1))) {
                next1 = CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            } else {
                uword *p = 0;
                p = hash_get (cm->gid_by_sw_if_index, sw_if_index1);
                if (PREDICT_FALSE(p == 0)) {
                    next1 = CTRLCAP_PUNT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    gid1 = p[0];

                    // set global interface id
                    cm->ip4_nsh_hdr.nsh.sph = gid1;

                    vlib_buffer_advance (b1, -(word)sizeof(ip4_nsh_header_t));
                    ip4_header_t *ip4_1 = vlib_buffer_get_current (b1);
    // copy 8-bytes at a time
#define _(off) ((u64 *)ip4_1)[off] = ((u64 *)&cm->ip4_nsh_hdr)[off];
                    foreach_fixed_header4_offset;
#undef _

                    // last 4 bytes
                    ((u32 *)ip4_1)[8] = ((u32 *)&cm->ip4_nsh_hdr)[8];

                    /* recalculate IP checksum */
                    sum1 = ip4_1->checksum;
                    new_l1 = 
                      clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));
                      sum0 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
                                           length /* changed member */);
                    ip4_1->checksum = ip_csum_fold (sum1);
                    ip4_1->length = new_l1;

                    /* recalculate UDP len */
                    udp1 = (udp_header_t *)(ip4_1+1);
                    new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1) - sizeof (*ip4_1));
                    udp1->length = new_l1;

                    //vnet_buffer(b1)->sw_if_index[VLIB_TX] = (u32)~0; //sw_if_index1;
                    pkts_punted += 1;
                }
            }

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
                if (b0->flags & VLIB_BUFFER_IS_TRACED)
                {
                    ctrlcap_punt_trace_t *t = 
                        vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                    t->gid = gid0;
                }
                if (b1->flags & VLIB_BUFFER_IS_TRACED)
                {
                    ctrlcap_punt_trace_t *t = 
                        vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                    t->gid = gid1;
                }
            }

            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t * b0;
            u32 next0 = CTRLCAP_PUNT_NEXT_IP4_LOOKUP; //CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            u32 sw_if_index0;
            udp_header_t * udp0;
            u16 old_l0 = 0;
            u16 new_l0;
            ip_csum_t sum0;
            u32 gid0 = ~0;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            /*
             * Direct from the driver, we should be at offset 0
             * aka at &b0->data[0]
             */
            ASSERT (b0->current_data == 0);
            ethernet_header_t *en0 = vlib_buffer_get_current (b0);

            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

            if (PREDICT_TRUE(!should_encap(en0))) {
                next0 = CTRLCAP_PUNT_NEXT_ETHERNET_INPUT;
            } else {
                uword *p = 0;
                p = hash_get (cm->gid_by_sw_if_index, sw_if_index0);
                if (PREDICT_FALSE(p == 0)) {
                    next0 = CTRLCAP_PUNT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    gid0 = p[0];
                    // set global interface id
                    cm->ip4_nsh_hdr.nsh.sph = gid0;

                    vlib_buffer_advance (b0, -(word)sizeof(ip4_nsh_header_t));
                    ip4_header_t *ip4_0 = vlib_buffer_get_current (b0);
    // copy 8-bytes at a time
#define _(off) ((u64 *)ip4_0)[off] = ((u64 *)&cm->ip4_nsh_hdr)[off];
                    foreach_fixed_header4_offset;
#undef _

                    // last 4 bytes
                    ((u32 *)ip4_0)[8] = ((u32 *)&cm->ip4_nsh_hdr)[8];

                    /* recalculate IP checksum */
                    sum0 = ip4_0->checksum;
                    new_l0 = 
                      clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
                      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                           length /* changed member */);
                    ip4_0->checksum = ip_csum_fold (sum0);
                    ip4_0->length = new_l0;

                    /* recalculate UDP len */
                    udp0 = (udp_header_t *)(ip4_0+1);
                    new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) - sizeof (*ip4_0));
                    udp0->length = new_l0;

                    //vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0; //sw_if_index0;
                    pkts_punted += 1;
                }
            }

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                              && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                ctrlcap_punt_trace_t *t = 
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->gid = gid0;
            }

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                           to_next, n_left_to_next,
                           bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, ctrlcap_punt_node.index, 
                               CTRLCAP_ERROR_PUNTED, pkts_punted);
    if (pkts_invalid > 0)
        vlib_node_increment_counter (vm, ctrlcap_inject_node.index,
                                   CTRLCAP_ERROR_INVALID, pkts_invalid);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE (ctrlcap_punt_node) = {
    .function = ctrlcap_punt_node_fn,
    .name = "ctrlcap-punt-nsh",
    .vector_size = sizeof (u32),
    .format_trace = format_ctrlcap_punt_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(ctrlcap_error_strings),
    .error_strings = ctrlcap_error_strings,

    .n_next_nodes = CTRLCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes = {
          [CTRLCAP_PUNT_NEXT_IP4_LOOKUP] = "ip4-lookup",
          [CTRLCAP_PUNT_NEXT_ETHERNET_INPUT] = "ethernet-input",
          [CTRLCAP_PUNT_NEXT_ERROR_DROP] = "error-drop",
    },
};

