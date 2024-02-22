# Learning-eBPF
[Learning-eBPF](https://github.com/lizrice/learning-ebpf)
![image](https://github.com/ziguin0925/web_1/assets/117524772/e6cdac90-6e7c-4779-838a-aa2bb760ff21)


위의 교재를 이용한 c언어로 시작하는 eBPF 기초 학습.


* bpf_helpers 함수
https://man7.org/linux/man-pages/man7/bpf-helpers.7.html




## 버전 확인 방법

- llvm(low level virtual machine)
```
$ llc --version
Ubuntu LLVM version 14.0.0
```


- clang
```
$ clang --version
Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- bpftool
```
$ bpftool version
bpftool v7.4.0
using libbpf v1.4
features: llvm, skeletons
```

- 패키지 libbpf
```
$ sudo dpkg -l | grep libbpf
libbpf-dev : 1:0.5.0-1ubuntu22.04.1   
```


### eBPF를 위한 다양한 확인 방법.

* 객체 파일 instruction 디스어셈블리어
```
$ llvm-objdump -S [object file]
```

* jited 컴파일 된 코드 디스어셈블.

jit(Just-in-time) - eBPF 바이트 코드를 CPU가 실행할 수 있는 머신코드로 변환한다.
```
$ sudo bpftool prog dump jited name [eBPF program name]
```

* xlated 바이트 코드 정보 확인.(얼마나 많은 eBPF 코드가 번역되었는지, verifier 통과 후)
```
$ sudo bpftool prog dump xlated name [eBPF program name]
```

* ELF 섹션 헤더 확인
```
$ readelf -S [object file]
```

* eBPF 프로그램 리스트
```
sudo bpftool (prog, map) list
```

* syscall argument 확인 
```
sudo cat /sys/kernel/debug/tracing/events/syscalls/[trace_point]/format
```

* bpf_printk(), bpf_trace_printk() 출력 확인
```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe   
```
![image](https://github.com/ziguin0925/web_1/assets/117524772/7a2c171e-9690-46e3-bfc6-feb090bd6160)


trace_pipe 출력 사항 정보.
https://www.kernel.org/doc/Documentation/trace/ftrace.txt








## 출력 확인
```
#chapter2
{	

	출력 가능

}


#chapter3
{

	hello.bpf.c : xdp에 pin 고정 안될 때 pin삭제 또는 reboot 후 출력가능.
	hello-func.bpf.c :bpftool prog 로드 가능, bpftool prog list에 나옴. 출력 불가.

    bpftool prog load ... [특정 인터페이스] 의 경우 교재에서는 eth0로 나오지만,  vm 에서는 enp0s3으로 나오므로 변경.
				
}


#chapter4
{

	출력 가능

}



#chapter5
{

	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 먼저 터미널에 입력해야 함.

	find me 			출력 가능
	hello-buffer-config 	출력 가능	
	

	hello-buffer-config strace -e bpf ./hello-buffer-config 입력 시

	#bpf(BPF_LINK_CREATE, {link_create={prog_fd=11, target_fd=-1, attach_type=BPF_PERF_EVENT, flags=0}}, 48) = -1 EBADF (파일 디스크립터가 잘못됨)

}



#chapter6 
{

	hello-verifier 		 출력가능
	xdp			출력 가능

	#bpf(BPF_LINK_CREATE, {link_create={prog_fd=11, target_fd=-1, attach_type=BPF_PERF_EVENT, flags=0}}, 48) = -1 EBADF (파일 디스크립터가 잘못됨)

}


#chapter7
{

	bpf_perf_event_output 출력? 안나옴.

	hello : 'fentry_execve': failed to find kernel BTF type ID of 'do_execve'
	kprobe at do_execve() - libbpf: prog 'kprobe_do_execve': failed to create kprobe 'do_execve+0x0' perf event: No such file or directory


    # bpftool v 7.1 부터 사용가능한 'bpftool prog load <object_file> <pinned_path> autoattach' 를 이용해 출력 확인.
}



#chapter8
{

	출력 가능

}
```