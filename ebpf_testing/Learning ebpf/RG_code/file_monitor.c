#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_monitor.skel.h"



struct args_t {     
   const char *fname;
   int flags;
};


struct event {
	/* user terminology for pid: */
	__u64 ts;
	pid_t pid;
	uid_t uid;
	int ret;
	int flags;
	__u64 callers[2];
	char comm[16];
	char fname[255];
};

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct event *e=data;
	
	printf("%-6d %-6d %-16s %x\n %s\n", e->pid, e->uid, e->comm ,e->flags, e->fname);
	printf("fd : %d\n", e->ret);
}

int main()
{
	struct perf_buffer *pb = NULL;
	struct file_monitor_bpf *obj;
	int err;
	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	obj = file_monitor_bpf__open_opts(&opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = file_monitor_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		return 1;
	}

	err = file_monitor_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 8,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);

	file_monitor_bpf__destroy(obj);

	return -err;









}





