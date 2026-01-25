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
#include <stdlib.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/unistd.h>

#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include "egress.h"

char cgroup_dir;
int dur = 1;

static void print_usage(void);

#define DEBUGFS "/sys/kernel/debug/tracing/"

static struct bpf_program *bpf_prog;
static struct bpf_object *obj;
static struct bpf_map *queue_state;
static struct bpf_map *queue_rate;
static int queue_state_fd;
static int queue_rate_fd;
static int cgroup_fd;

static int prog_load(char *prog)
{
  struct bpf_program *pos;
	const char *sec_name;

	obj = bpf_object__open_file(prog, NULL);
	if (libbpf_get_error(obj)) {
		printf("ERROR: opening BPF object file failed\n");
    bpf_object__close(obj);
		return 1;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		printf("ERROR: loading BPF object file failed\n");
    bpf_object__close(obj);
    return 1;
	}

	bpf_object__for_each_program(pos, obj) {
		sec_name = bpf_program__section_name(pos);
		if (sec_name && !strcmp(sec_name, "cgroup_skb/egress")) {
			bpf_prog = pos;
			break;
		}
	}

	if (!bpf_prog) {
		printf("ERROR: finding a prog in obj file failed\n");
		return 1;
	}

	/* Check BPF maps exists */
	queue_state_fd = bpf_object__find_map_fd_by_name(obj, "queue_state");
	if (queue_state_fd < 0) {
		printf("ERROR: finding a map in obj file failed\n");
		bpf_object__close(obj);
    return 1;
	}

	queue_rate_fd = bpf_object__find_map_fd_by_name(obj, "queue_rate");
	if (queue_rate_fd < 0) {
		printf("ERROR: finding a map in obj file failed\n");
		bpf_object__close(obj);
    return 1;
	}

	return 0;
}


/*
 * Attach BPF program to cgroup.
*/
static int run_bpf_prog(char *prog, char *cgroup_dir, uint64_t mbps)
{
	int key = 0;
	uint64_t rate = 0;
	char cg_dir[100], cg_pin_path[100];
	struct bpf_link *link = NULL;
	int rc = 0;

	rc = prog_load(prog);
	if (rc != 0) {
		return rc;
	}

	rate = (uint64_t)(mbps);
	queue_rate = bpf_object__find_map_by_name(obj, "queue_rate");
	cgroup_fd = open(cgroup_dir, O_RDONLY);

	printf("rate set to %lu Mbps per second\n", rate);

	if (bpf_map__update_elem(queue_rate, &key, 4, &rate, 8, BPF_ANY)) {
		printf("ERROR: Could not update map element\n");
		rc = 1;
	}

	link = bpf_program__attach_cgroup(bpf_prog, cgroup_fd);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach_cgroup failed\n");
		rc = 1;
	}

	sprintf(cg_pin_path, "/sys/fs/bpf/%s", cgroup_dir);

	rc = bpf_link__pin(link, cg_pin_path);
	printf("Pinning egress program to %s\n", cg_pin_path);
	if (rc < 0) {
		printf("ERROR: bpf_link__pin failed: %d\n", rc);
		rc = 1;
	}

	sleep(dur);

	bpf_link__destroy(link);
	bpf_object__close(obj);

	return rc;
}

void print_usage(void) {
  fprintf(stderr, "cgroup_outbound_bandwidth_bpf\n");
  fprintf(stderr, "Set outbound bandwidth limit for a cgroup\n");
  fprintf(stderr, "usage: egress <cgroup directory> <outbound bandwidth Megabit per seconds>\n");
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{

	uid_t euid = geteuid();

    if (euid != 0) {
        printf("Promote to root...\n");
        char **new_argv = malloc(sizeof(char *) * (argc + 2));

        new_argv[0] = "sudo";

        for (int i = 0; i < argc; i++) {
            new_argv[i + 1] = argv[i];
        }

        new_argv[argc + 1] = NULL;

        execvp("sudo", new_argv);
        perror("execvp failed");
        exit(1);
    }

	char *prog = "egress_bpf.o";

	if (argc != 3) {
		print_usage();
		return 1;
	}

	char *cgroup_dir = argv[1];
	uint64_t mbps = atoi(argv[2]);
	printf("cgroup dir: %s\n", cgroup_dir);
	printf("egress rate limit: %lu Mbps\n", mbps);
	printf("HBM prog: %s\n", prog != NULL ? prog : "NULL");

	return run_bpf_prog(prog, cgroup_dir, mbps);
}
