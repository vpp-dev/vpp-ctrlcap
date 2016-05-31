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

#define CHECK_NSH_VALID     0
#define CHECK_NSH_NOTNSH    1
#define CHECK_NSH_INVALID   2

typedef struct {
    u32 next_index;
    u32 rx_sw_if_index;
    u32 tx_sw_if_index;
    u32 gid;
    u8 action;
} ctrlcap_inject_trace_t;

/* packet trace format function */
static u8 * format_ctrlcap_inject_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ctrlcap_inject_trace_t * t = va_arg (*args, ctrlcap_inject_trace_t *);

    s = format (s, "ctrlcap inject: rx sw_if_index %d, tx sw_if_index %d, next index %d, gid %d\n",
                t->rx_sw_if_index, t->tx_sw_if_index, t->next_index, t->gid);
    if (t->action == CHECK_NSH_VALID)
        s = format (s, "    action: injected");
    else if (t->action == CHECK_NSH_INVALID)
        s = format (s, "    action: dropped");
    else
        s = format (s, "    action: ethernet-input");
    return s;
}

vlib_node_registration_t ctrlcap_inject_node;

#define foreach_ctrlcap_error \
_(INJECTED, "Packets injected") \
_(INVALID, "Invalid nsh packets")

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
    CTRLCAP_INJECT_NEXT_ETHERNET_INPUT,
    CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT,
    CTRLCAP_INJECT_NEXT_ERROR_DROP,
    CTRLCAP_N_NEXT,
} ctrlcap_next_t;

static u8 check_nsh(ethernet_header_t *en)
{
    // ipv4
    if (en->type != 0x0800)
        return CHECK_NSH_NOTNSH;

    ip4_nsh_header_t *ip4_nsh = (ip4_nsh_header_t *)(en+1);
    // UDP
    if (ip4_nsh->ip4.protocol != 0x11)
        return CHECK_NSH_NOTNSH;

    if (ip4_nsh->udp.length - sizeof(ip4_nsh->udp) < sizeof(nsh_header_t))
        return CHECK_NSH_NOTNSH;

    if (ip4_nsh->nsh.flags != 0x0
        || ip4_nsh->nsh.rr_len != 0x2
        || ip4_nsh->nsh.md_type != 0x2
        || ip4_nsh->nsh.next_proto != 0x3)
        return CHECK_NSH_INVALID;

    return CHECK_NSH_VALID;
}

static uword
ctrlcap_inject_node_fn (vlib_main_t * vm,
          vlib_node_runtime_t * node,
          vlib_frame_t * frame)
{
    ctrlcap_main_t *cm = &ctrlcap_main;
    u32 n_left_from, * from, * to_next;
    ctrlcap_next_t next_index;
    u32 pkts_injected = 0;
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
            u32 next0 = CTRLCAP_INJECT_NEXT_ETHERNET_INPUT; //CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT;
            u32 next1 = CTRLCAP_INJECT_NEXT_ETHERNET_INPUT; //CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT;
            u32 sw_if_index0 = ~0, sw_if_index1 = ~0;
            u32 tx_sw_if_index0 = ~0, tx_sw_if_index1 = ~0;
            u32 bi0, bi1;
            vlib_buffer_t * b0, * b1;
            u32 gid0 = ~0, gid1 = ~0;
          
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

            u8 rc0 = check_nsh(en0);
            u8 rc1 = check_nsh(en1);

            if (PREDICT_TRUE(rc0 == CHECK_NSH_VALID)) {
                ip4_nsh_header_t *ip4_nsh = (ip4_nsh_header_t *)(en0+1);
                gid0 = clib_host_to_net_u16(ip4_nsh->nsh.sph);
                uword *p = 0;
                p = hash_get (cm->sw_if_index_by_gid, gid0);
                if (PREDICT_FALSE(p == 0)) {
                    next0 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    tx_sw_if_index0 = p[0];
                    next0 = CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT;

                    // move buffer after the nsh header
                    vlib_buffer_advance (b0, (word)(sizeof(ethernet_header_t) + sizeof(ip4_nsh_header_t)));
                    vnet_buffer(b0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
                    pkts_injected += 1;
                }
            } else if (PREDICT_FALSE(rc0 == CHECK_NSH_INVALID)) {
                // invalid NSH packets
                next0 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                pkts_invalid += 1;
            }

            if (PREDICT_TRUE(rc1 == CHECK_NSH_VALID)) {
                ip4_nsh_header_t *ip4_nsh = (ip4_nsh_header_t *)(en1+1);
                gid1 = clib_host_to_net_u16(ip4_nsh->nsh.sph);
                uword *p = 0;
                p = hash_get (cm->sw_if_index_by_gid, gid1);
                if (PREDICT_FALSE(p == 0)) {
                    next1 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    tx_sw_if_index1 = p[0];

                    next1 = CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT;

                    // move buffer after the nsh header
                    vlib_buffer_advance (b1, (word)(sizeof(ethernet_header_t) + sizeof(ip4_nsh_header_t)));
                    vnet_buffer(b1)->sw_if_index[VLIB_TX] = tx_sw_if_index1;
                    pkts_injected += 1;
                }
            } else if (PREDICT_FALSE(rc1 == CHECK_NSH_INVALID)) {
                next1 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                pkts_invalid += 1;
            }

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
                if (b0->flags & VLIB_BUFFER_IS_TRACED)
                {
                    ctrlcap_inject_trace_t *t = 
                        vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->rx_sw_if_index = sw_if_index0;
                    t->tx_sw_if_index = tx_sw_if_index0;
                    t->next_index = next0;
                    t->gid = gid0;
                    t->action = rc0;
                }
                if (b1->flags & VLIB_BUFFER_IS_TRACED)
                {
                    ctrlcap_inject_trace_t *t = 
                        vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->rx_sw_if_index = sw_if_index1;
                    t->tx_sw_if_index = tx_sw_if_index1;
                    t->next_index = next1;
                    t->gid = gid1;
                    t->action = rc1;
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
            u32 next0 = CTRLCAP_INJECT_NEXT_ETHERNET_INPUT;
            u32 sw_if_index0 = ~0;
            u32 tx_sw_if_index0 = ~0;
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
            u8 rc0 = check_nsh(en0);

            if (PREDICT_TRUE(rc0 == CHECK_NSH_VALID)) {
                ip4_nsh_header_t *ip4_nsh = (ip4_nsh_header_t *)(en0+1);
                u32 gid0 = clib_host_to_net_u16(ip4_nsh->nsh.sph);
                uword *p = 0;
                p = hash_get (cm->sw_if_index_by_gid, gid0);
                if (PREDICT_FALSE(p == 0)) {
                    next0 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                    pkts_invalid += 1;
                } else {
                    tx_sw_if_index0 = p[0];

                    next0 = CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT;

                    // move buffer after the nsh header
                    vlib_buffer_advance (b0, (word)(sizeof(ethernet_header_t) + sizeof(ip4_nsh_header_t)));
                    vnet_buffer(b0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
                    pkts_injected += 1;
                }
            } else if (PREDICT_FALSE(rc0 == CHECK_NSH_INVALID)) {
                next0 = CTRLCAP_INJECT_NEXT_ERROR_DROP;
                pkts_invalid += 1;
            }

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                              && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                ctrlcap_inject_trace_t *t = 
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->rx_sw_if_index = sw_if_index0;
                t->tx_sw_if_index = tx_sw_if_index0;
                t->next_index = next0;
                t->gid = gid0;
                t->action = rc0;
            }

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                           to_next, n_left_to_next,
                           bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, ctrlcap_inject_node.index,
                               CTRLCAP_ERROR_INJECTED, pkts_injected);
    if (pkts_invalid > 0)
        vlib_node_increment_counter (vm, ctrlcap_inject_node.index,
                                   CTRLCAP_ERROR_INVALID, pkts_invalid);

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (ctrlcap_inject_node) = {
    .function = ctrlcap_inject_node_fn,
    .name = "ctrlcap-inject-nsh",
    .vector_size = sizeof (u32),
    .format_trace = format_ctrlcap_inject_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(ctrlcap_error_strings),
    .error_strings = ctrlcap_error_strings,

    .n_next_nodes = CTRLCAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes = {
          [CTRLCAP_INJECT_NEXT_ETHERNET_INPUT] = "ethernet-input",
          [CTRLCAP_INJECT_NEXT_INTERFACE_OUTPUT] = "interface-output",
          [CTRLCAP_INJECT_NEXT_ERROR_DROP] = "error-drop",
    },
};

