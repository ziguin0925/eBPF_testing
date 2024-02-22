# bpf2go
Cilium 프로젝트의 일부로 포함된 eBPF Go 라이브러리로, go를 이용해 eBPF프로그램 사용하기위한 툴체인 입니다.
CO-RE 지원을 포함하여 eBPF 프로그램 및 맵을 관리하고 로드하기 위한 편리한 기능을 제공합니다.
Go 코드가 컴파일되면 eBPF 바이트코드를 포함하고 Linux 커널 자체 이외의 종속성 없이 다른 커널
로 이식 가능한 단일 Go 바이너리를 배포할 수 있습니다.

bpf2go는 C 소스 파일을 eBPF 바이트코드로 컴파일하고 그 다음 eBPF를 포함하는 Go 파일을 생성합니다.

eBPF programm (.c)  -> (eb, el).go,  *(eb, el).o

eb(빅 엔디안), el(리틀 엔디안)입니다.
bpf2go 는 c언어의 ebpf프로그램 파일을 ebpf바이트 코드로  컴파일(go 파일에서 쓸수 있도록)하고, eBPF를 포함할 수 있는 go 파일(스켈레톤과 같은)을 내보냅니다.
자동 생성된 Go 코드에는 모든 맵과 프로그램을 나타내는 구조가 포함되어 있습니다.


## bpf2go 사용법 

사용자 공간 코드

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG  -cflags $BPF_CFLAGS bpf [C filename] -- -I../headers

위의 build tag 달아 줌.
해당 주소의 bpf2go 를 이용하여 eBPF프로그램 c 파일로 go 스켈레톤 코드와 eBPF 프로그램을 go 에서 쓸 수 있도록 rebuild 



* 만든 c ebpf 코드 bpf2go 이용해서 바꾸는 방법.

https://ebpf-go.dev/guides/getting-started/#ebpf-c-program

같은 디렉터리에서 실행할 것.
---
1. c코드 ebpf 프로그램 작성(커널 용)
코드 맨 처음에 
```
//go:build ignore
```
해당 c 파일을 무시하라는 코드 작성해야함***



2. go 파일 작성 (ebpf 프로그램을 bpf2go 이용하여 객체파일(.o)과 스켈레톤 파일(.go) 생성)

해당 go 파일 안에 내용(이름은 아무렇게나 해도된다.)
```
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c
```
(//...) : 터미널에 go generate 입력시 go run ...bpf2go를 통해  counter.c 를 counter라는 이름의 스켈레톤 파일과 객체 파일을 생성할 것이라는 문구



3. 터미널에 go mod init ebpf-test 입력(나중에 실행 파일 이름이 ebpf-test로 됨)
	module ebpf-test라는 내용을 가지고 있는 go.mod 파일 생성
	

4. 터미널에 go mod tidy 입력
	URL 같은 주소 가지고 있는 go.sum이라는 파일 생성.
	go mod에 require 코드가 생성됨.

5. 터미널에 go get github.com/cilium/ebpf/cmd/bpf2go입력


6. 터미널에 go generate 
	ebpf 프로그램 당 객체 파일 생성 2개,스켈레톤 코드 2개(go) 생성.

7. 스켈레톤 코드 이용해서 사용자 공간 코드 작성.

8. go build && sudo ./ebpf-test 입력 

```
//go : generate : generate tag
//go : build  :  build tag
```

## 환경
1.20이상의 go 설치 필요.
[go version download](https://go.dev/dl/)


1.20 이상 버전 PATH 설정

홈 디렉터리의 .basgrc에 아래 코드를 가장 윗줄에 저장. 
```
export PATH=$PATH:/usr/local/go/bin
```


* go version 검사
```
$ go version
go version go1.21.6 linux/amd64

```

## ebpf/example RUN
```
$ cd ebpf/example
$ go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
```
![image](https://github.com/ziguin0925/web_1/assets/117524772/dfaa33a5-f70d-44f3-8574-bd2cf22e3c8e)