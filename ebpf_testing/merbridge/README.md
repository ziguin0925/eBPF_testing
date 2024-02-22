# Merbridge

[Merbridge](https://github.com/merbridge/merbridge)


Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.


Cloud로 환경 시스템 운영시에 Service Mesh의 이점을 극대화 하기위해 만들어졌습니다.
Service Mesh란 애플리케이션의 다양한 부분들이 서로 데이터를 공유하는 방식을 제어하는 방법입니다.
서비스 메쉬를 구성하는 개별 프록시는 서비스 내부가 아니라 각 서비스와 함께 실행되므로 'sidecar'라고도 합니다. 각 서비스에서 분리된 이러한 sidecar 프록시들이 모여 메쉬 네트워크를 형성합니다.

iptable의 규칙을 새롭게 변경하여 인바운드, 아웃바운드 소켓의 데이터를 eBPF가 직접 전송할 수 있도록합니다. 
즉 데이터의 송수신 경로를 짧게 하여 속도를 높입니다.

![image](https://github.com/ziguin0925/web_1/assets/117524772/46374f79-7906-4122-9c20-8d9631f88e45)

ebpf는 실행에 영향을 미치지 않기 때문에 실행 중에 해제하여도 영향이 가지 않는다.(사이드카)



패킷이 envoy proxy를 거쳐 가도록 vm에서 eBPF프로그램을 이용하여 local에서 테스트



 - guest.py : VM에서 동작
 - host.py  : host에서 동작

Guset pc 에서 Host pc로 socket 연결하도록
 
 ![image](https://github.com/ziguin0925/web_1/assets/117524772/0d409765-d868-4291-a2b6-c3c167b8578a)
 
 
 

## eBPF code
* bpf_bind(), 및 ctx ip, port 변환
```
#define IN_REDIRECT_PORT 15006

```
0100007f= 127.0.0.1 = localhost


특정 소켓을 특정 IP 주소로 바인딩하여 그 IP 주소를 사용하여 다른 호스트로 연결을 만들 수 있도록 합니다.

## 실행 환경

**Ubuntu**
- 22.04
- 6.5.0-17-generic


**bpftool v5.4.0 가져오기.**
```
git clone -b v5.4 https://github.com/torvalds/linux.git --depth 1
cd /linux/tools/bpf/bpftool && \
    make && make install
```
tools디렉터리에 bpftool v5.4.0가져옴



**envoy**

istio에서 사용되는 Dynamic forward proxy로 L4,L7기능을 지원한다.
네트워킹 활동에 대해 개입이 가능하고, 관측가능성까지 부여할 수 있다.
- 1.18.2


https://www.envoyproxy.io/docs/envoy/latest/start/start

## RUN

```
$ make
$ envoy -c envoy-demo.yaml 
```


make만 했을 때 envoy 로그가 안뜨는 경우
```
$ make
$ make load && make attach
$ envoy -c envoy-demo.yaml 
```

merbridge bpf프로그램 내에 printk()는 에러 검출시 출력을 하도록 되어있음. 
debug 옵션을 줌으로 debugf()를 통해 과정을 확인할 수 있는데, 옵션을 줄 경우 실행이 안되는 에러가 발생하므로 bpf디렉터리의 소스 파일에서 원하는 위치에 printk()로 출력해주기.



## 출력 확인 

```
- Terminal 1
$ envoy -c envoy-demo.yaml

- Terminal 2(client)
python3 ./guest.py

- Host pc(server) 
host.py 실행(run)

```
![image](https://github.com/ziguin0925/web_1/assets/117524772/ed5c2ffa-e957-40c6-93bf-64ec60ac0ac2)



wireshark를 통한 확인.
![image](https://github.com/ziguin0925/web_1/assets/117524772/7fd19ae5-9bf3-4be6-88be-cfde48e0acbf)
