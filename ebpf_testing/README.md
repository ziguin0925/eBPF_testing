# eBPF

eBPF(extended Berkeley Packet Filter)


커널 소스 코드를 바꾸거나 추가 모듈을 추가할 필요 없이 프로그램을 운영체제의 커널 공간에서 실행하는 기술로서 OS커널 수준부터 전체 소프트웨어 스택에 걸쳐 관측 및 네트워킹 및 보안을 위한 프로그래밍을 가능하게 하는 기술입니다.

현재 퍼블릭, 프라이빗, 하이브리드 클라우드와 같은 동적인 환경에서
확장성 있는 애플리케이션을 구축하고 실행할 수 있도록 하는 기술인 
클라우드 네이티브 분야에서 많이 사용이 되는 것으로 파악이 됩니다.


Networking, Obervability, Tracing&Profiling, Security 측면에서 사용이 가능하며,
주로 커널 내에서 발생하는 이벤트에 대해 관측가능성을 부여하고, 모니터링하면서 위협에 대응하는 방법으로 사용합니다.

Data Loss Prevent와 Endpoint Detection and Response를 위한 local에서의 테스트를 목적으로, 
다른 프로젝트의 소스를 가져와 local에서 작동할 수 있도록 수정 및 개발.

## eBPF 원리 
![image](https://github.com/ziguin0925/web_1/assets/117524772/5ff95914-8385-4498-b9ee-7594bf09917a)




1. eBPF 객체 파일 컴파일
  (Clang –target bpf)

2. 커널에 프로그램 로드
  (bpftool prog load [파일명]  [경로])

3. JIT 컴파일된 기계어 코드
	트리거 될 경우 JIT 컴파일러 작동,
	kernel과 userspace 상호작용


Verifier는 레지스터를 통해 가능한 모든 실행 경로를 평가하여,  
잘못된 작업을 초래할 수 있는 명령을 찾으면 확인에 실패하는것을 통해  eBPF프로그램이 안전한지 확인한다.
명령어 처리 수는 100만개로 제한되어있다.


위의 과정으로 eBPF프로그램을 특정 syscall(kernel event)에 attach한다.
임의의 프로세스가 특정 syscall(kernel event)에 접근하면 attach되어있는 
사용자가 정의한 eBPF프로그램이 실행된다.

## 기초 환경 설정

[learning-eBPF](https://github.com/lizrice/learning-ebpf)에서 기초 예제를 실행해 보기 위한 환경.

**Ubuntu**

- 22.04.1-Ubuntu
- 6.5.0-17-generic


**필요 패키지**
```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf libcap-dev
```
libbpf, bpftool, bcc 같은 경우 위의  learning-ebpf링크에 들어가 기재된 대로 설치




~~실행시 아래 오류에 대한 해결 방법~~


(AttributeError: /lib/x86_64-linux-gnu/libbcc.so.0: undefined symbol: bpf_module_create_b)
```
sudo rm -rf /usr/lib/python3/dist-packages/bcc/
cd bcc/build/
sudo make install
```



## 디렉터리별 요약

* **Learning ebpf**

  eBPF 상세 개념 및 학습을 위한 기초 txt파일, 
  eBPF 로그 및 데이터 보는법


* **bpf2go**

  go를 이용한 eBPF프로그램 기초


* **elastic**

  eBPF프로그램을 이용한 커널 내 SIGKILL Test  


* **lsmtrace**

  LSM(Linux Security Module)을 이용한 eBPF permission denined


* **merbridge**

  TCP 연결 리다이렉션 및 포워딩 테스트 관련



### update submodule
```
$ git submodule update --init --recursive
```


### 다른 프로젝트

* [redcanary](https://github.com/redcanaryco/redcanary-ebpf-sensor.git)
sensor형태의 linux EDR ebpf 프로젝트, CLI가 없고 oxide bpf를 활용하라고 한다.

elastic과 hook 지점 비교와 커널 함수 호출 순서 파악.

PERCPU(map)
leanrning ebpf 3장에 나와있는것처럼 ebpf프로그램의 스택데이터틑 512바이트가 한계라고한다.
따라서 다양한 프로젝트에서는 Array, percpu map을 힙처럼 사용한다고한다.(주로 파일 경로)
eBPF 프로그램은 비선점형이지만 시스템 콜은 선점형이라고 합니다. kprobe와 kretprobe는 다른 cpu에서 발생할 수 있다고 합니다.
이를 보완하기위해 비선점형인 tail call을 사용하여 정보를 전달합니다.  
    ##libbpf v1.0부터 legacy BPF map선언 지원 안함.(maps)




* [tetragon](https://github.com/cilium/tetragon.git)
eBPF를 기반으로한 런타임 보안 도구로 시스템 콜 뿐만아니라 커널 서브시스템 네임스페이스, 파일시스템과 데이터 접근, HTTP,DNS,TLS,TCP와 같은 네트워크 활동에 대한 가시성을 부여한다.
관리자가 정의한 정책을 기반으로 sensor, filter의 역할이 가능하다.
dentry 이용한 파일 경로 추출 과정 lsmtrace/RG_code에 적용.



