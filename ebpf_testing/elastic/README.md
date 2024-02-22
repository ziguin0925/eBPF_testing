# Elastic

* Elastic Endpoint on Linux

Event sourcing과 host isolation관련된 기술을 다루고 있습니다.
Event sourcing의 eBPF 프로그램 소스코드는  GPL/Events 디렉터리에 정리되어있고, User space 코드는 non-GPL/Events 디렉터리에 정리되어있습니다.


Host isolation eBPF 프로그램 소스코드는 GPL/HostIsolation 디렉터리에 정리되어있고, User space 코드는 non-GPL/HostIsolation 디렉터리에 정리되어있습니다.


[elastic ebpf github](https://github.com/elastic/ebpf.git)



![image](https://github.com/ziguin0925/web_1/assets/117524772/38d857bf-911c-44bb-bfb4-d67278d6dbd4)
![image](https://github.com/ziguin0925/web_1/assets/117524772/0871bc24-dcc2-455d-923c-28ff0911679b)

* do_unlinkat에 2개의 fentry를 부착할 경우 출력이 되는것으로 확인.


## Sigkill

* bpf_send_signal();

signal 확인 (/usr/include/x86_64-linux-gnu/bits/signum-generic.h)

커널 공간에서 원하는 hook 포인트에 sigkill code를 입력하여 
직접 신호를 보내 사용자 공간의 추가 오버헤드를 피함으로써 
이벤트가 발생한 직후 신호를 보낼 수 있어 대기 시간이 크게 단축됩니다.
SIGNAL은 안전한 지점에서 확인되어야 한다고 합니다.


chmod가 트리거 될 때 bpf_send_signal()을 통해 sigkill을 전달 할 경우 프로세스가 chmod 수행을 마치고 난 뒤에 sigkill을 읽어 kill되는것으로 확인이 되었습니다.(elastic/ebpf의 test_bins소스파일 활용)
![image](https://github.com/ziguin0925/web_1/assets/117524772/7b85411c-6857-4e62-a174-e63d2c3bf448)

[eunomia](https://eunomia.dev/tutorials/25-signal/),
[elastic security labs ](https://www.elastic.co/security-labs/signaling-from-within-how-ebpf-interacts-with-signals) 



## code

ebpf프로그램에 있는 kprobe/kretprobe 와 fentry/fexit의 경우 **ebpf/non-GPL/Events/Lib/EbpfEvents.c**에 의해 하나만 load 될 수 있도록 정의되어있습니다.
hook 포인트를 추가해줄 경우 수정이 필요합니다. 

eBPF 프로그램에서 bpf_ringbuf_output()을 이용하여 유저공간으로 전송합니다. 

RG_codeFile에 있는 소스 코드의 경우 ebpf/GPL/Events/File/Probe.bpf.c와 바꾸어 줄 경우 chmod 트리거시 process kill signal 전송. 
bpf_send_signal_thread()의 경우도 있다고 합니다.


## RUN

```
$ git clone https://github.com/elastic/ebpf.git
$ cd ebpf
$ make
$ cd artifacts-x86_64/non-GPL/Events/EventsTrace
$ sudo ./EventsTrace --file-create

  {"event_type":"FILE_CREATE","pids":{"tid":208,"tgid":208,"ppid":1,"pgid":208,"sid":208,"start_time_ns":2537123204},"mount_namespace":4026531841,"comm":"systemd-journal","file_info":{"type":"FILE","inode":3381,"mode":100600,"size":0,"uid":0,"gid":0,"atime":1708479701689382915,"mtime":1708479701689382915,"ctime":1708479701689382915},"path":"/run/systemd/journal/streams/.#8:120319L8bJJH","symlink_target_path":""}
  ...

```
![image](https://github.com/ziguin0925/web_1/assets/117524772/3ff0c81b-5c21-463e-a46e-005bb36adff6)