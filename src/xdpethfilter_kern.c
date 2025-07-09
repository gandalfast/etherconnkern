#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "myfilter.h"

// etype_list list all ethertypes that need to redirect to XDP socket
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NUM_ETYPE_ENTRY);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
} etype_list SEC(".maps");
// following maps are used for XDP socket

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SOCKS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} qidconf_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SOCKS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

SEC("xdp_filter")
int xdp_redirect_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    unsigned short eth_type;
    sizeof(void *);

    /* These keep track of the next header type and iterator pointer */
    nh.pos = data;

    /* Parse Ethernet header*/
    eth_type = bpf_ntohs(parse_ethhdr(&nh, data_end, &eth));
    void *result;
    result = bpf_map_lookup_elem(&etype_list, &eth_type);
    if (!result) // rcvd pkt doesn't have expected etherType, pass it to kernel
        return XDP_PASS;
    int index = ctx->rx_queue_index;
    int *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
    if (!qidconf)
        return XDP_ABORTED;

    return bpf_redirect_map(&xsks_map, index, 0);
}

/* xdp_pass is used to attach to egress interface, this is due to limitation
that xdp_redirect require a XDP program not only in ingress interface, but
also a dummy one on all egress interface AND its peer (in case of veth).
see https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting
*/
SEC("xdp_pass_sec")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";