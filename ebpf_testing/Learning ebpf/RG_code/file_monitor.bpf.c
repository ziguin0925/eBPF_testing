#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


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


struct args_t {     
   const char *fname;
   int flags;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
}start SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
}events SEC(".maps");



//vmlinux에 struct trace_event_raw_sys_enter가 정의되어있습니다. 

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{

	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 pid = id;

	
	struct args_t args = {};
	args.fname = (const char *)ctx->args[1];
	args.flags = (int)ctx->args[2];
	bpf_map_update_elem(&start, &pid, &args, 0);

	return 0;
	
}



static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;
	uintptr_t stack[3];
	int ret;

	u32 pid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	
	ret = ctx->ret;

	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	event.flags = ap->flags;
	event.ret = ret;
	

	

	bpf_get_stack(ctx, &stack, sizeof(stack),BPF_F_USER_STACK);

	/* Skip the first address that is usually the syscall it-self */

	event.callers[0] = stack[1];
	event.callers[1] = stack[2];
	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,&event, sizeof(event));
	bpf_map_delete_elem(&start, &pid);

	return 0;

}



SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);

}



/*
struct {

	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, );
} start SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_newfstatat")
int tracepoint__syscalls__sys_enter_newfstatat(struct trace_event_raw_sys_enter* ctx)
{
	struct stat stat={};
	struct atgs_new args={};
	const char *fname;
	fname = (const char *)ctx->args[1];
	stat = ctx->args[2];

	bpf_get_current_pid_tgid() >> 32;
	//map하나 만들어서 key에 경로, value에 st_mode.
	//st_mode 출력 되면 stat 전부 value로 옮겨보기 
	return 0;
}
*/
char LICENSE[] SEC("license") = "GPL";



