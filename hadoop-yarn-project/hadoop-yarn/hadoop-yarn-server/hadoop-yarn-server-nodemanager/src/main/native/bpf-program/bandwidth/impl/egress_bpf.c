/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "egress.h"

#define DROP_PKT	0
#define ALLOW_PKT	1

struct pkt_info {
		bool	is_tcp;
		short	ecn;
};

// Define BPF Map
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, struct vqueue);
} queue_state SEC(".maps");

// Just for pass rate
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} queue_rate SEC(".maps");

SEC("cgroup_skb/egress")
int cg_limit_outbound_bandwidth(struct __sk_buff *skb)
{
	struct pkt_info pkti;
	int len = skb->len;
	unsigned int queue_index = 0;
	unsigned long long curtime;
	uint64_t credit;
	uint64_t cost;
	signed long long delta = 0, new_credit;
	bool drop_flag = false;
	bool cwr_flag = false;
	bool ecn_ce_flag = false;
	struct vqueue *qdp;
	// int rate;
	int rv = ALLOW_PKT;
	struct iphdr iph;
	struct ipv6hdr *ip6h;

	bpf_skb_load_bytes(skb, 0, &iph, 12);
	if (iph.version == 6) {
		ip6h = (struct ipv6hdr *)&iph;
		pkti.is_tcp = (ip6h->nexthdr == 6);
	} else if (iph.version == 4) {
		pkti.is_tcp = (iph.protocol == 6);
	} else {
		pkti.is_tcp = false;
	}

	// We may want to account for the length of headers in len
	// calculation, like ETH header + overhead, specially if it
	// is a gso packet. But I am not doing it right now.

	qdp = bpf_get_local_storage(&queue_state, 0);
	
	int key = 0;
	unsigned int *rate = bpf_map_lookup_elem(&queue_rate, &key);

	if (!qdp || !rate) {
		return ALLOW_PKT;
		bpf_printk("ALLOW_PKT! (!qdp || !rate) skb len: %d\n", len);
	} else if (qdp->lasttime == 0) {
		qdp->lasttime = bpf_ktime_get_ns();		
		qdp->rate = *rate;
		qdp->credit = qdp->rate;
	}

	curtime = bpf_ktime_get_ns();

	// critical section
	bpf_spin_lock(&qdp->lock);
	credit = qdp->credit;
	delta = curtime - qdp->lasttime;
	/* delta < 0 implies that another process with a curtime greater
	 * than ours beat us to the critical section and already added
	 * the new credit, so we should not add it ourselves
	 */

	/* Time in nanoseconds is used as a resource (credit).
     * For example, when the rate is 1Mbps, the nanosecond time required to send 1 byte is 8000ns.
     * Therefore, the time calculated as packet length * 8000 / rate is deducted from the credit.
     * The credit is replenished by delta nanoseconds.
     * If it becomes negative, it indicates exceeding the bandwidth, so the packet is dropped.
	 */
	if (delta > 0) {
		qdp->lasttime = curtime;
		new_credit = credit + ((int)(delta));
		if (new_credit > ((1500 * 8 * 1000) / qdp->rate))
			credit = qdp->rate;
		else
			credit = new_credit;
	}

	cost = ((uint64_t)len * 8 * 1000) / (uint64_t)qdp->rate;
	if (cost > credit) {
		drop_flag = true;
		if (pkti.is_tcp)
			cwr_flag = true;
	} else {
		credit -= cost;
		qdp->credit = credit;
	}
	bpf_spin_unlock(&qdp->lock);
	// End critical section

//	bpf_printk("delta: %d\n", delta);
//	bpf_printk("credit: %u, len: %d, cost: %u\n", credit, len, cost);

	if (drop_flag) {
		__sync_add_and_fetch(&(qdp->credit), len);
		rv = DROP_PKT;
//		bpf_printk("DROP!!!!!!!");
	}
	return rv;
}

char _license[] SEC("license") = "GPL";
