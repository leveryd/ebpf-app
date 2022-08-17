ebpf_app:
	clang -O2 -g -Wall -target bpf -c xdp_udp_backdoor.bpf.c -o xdp_udp_backdoor_bpf.o
load: ebpf_app
	ip link set eth0 xdpgeneric off
	ip link set eth0 xdpgeneric obj xdp_udp_backdoor_bpf.o sec xdp_backdoor
skel: ebpf_app
	bpftool gen skeleton xdp_udp_backdoor_bpf.o > xdp_udp_backdoor_bpf.h
app: skel
	clang -lelf -lz -lbpf  xdp_udp_backdoor.c
clean:
	rm -f xdp_udp_backdoor_bpf.o a.out xdp_udp_backdoor_bpf.h


