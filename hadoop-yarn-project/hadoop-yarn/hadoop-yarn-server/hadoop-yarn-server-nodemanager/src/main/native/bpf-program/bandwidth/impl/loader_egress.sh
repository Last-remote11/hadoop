clang -g -O2 -o egress egress.c /usr/src/kernels/5.14.0-503.40.1.el9_5.x86_64/tools/lib/bpf/libbpf.a -lelf -lz

# 실제로 성공하는 놈
clang -g -O0 -o egress egress.c /usr/src/kernels/5.14.0-503.40.1.el9_5.x86_64/tools/lib/bpf/libbpf.a -lelf -lz

clang -O2 -target bpf -c -g egress_bpf.c -o egress_bpf.o 