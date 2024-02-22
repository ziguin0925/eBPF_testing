# some makefile commands used by merbridge
load:
	[ -f bpf/mb_connect.c ] && make -C bpf load || make -C bpf load-from-obj
attach:
	make -C bpf attach
clean:
	make -C bpf clean
compile:
	make -C bpf compile

generate-compilation-database:
	make -f bpf/Makefile generate-compilation-database

lint-c:
	clang-format --Werror -n bpf/*.c bpf/headers/*.h

format-c:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

lint-go:
	golangci-lint run

format-go:
	goimports -w -local github.com/merbridge/merbridge/ .
	gofmt -l -d -w .

lint: lint-c lint-go

format: format-c format-go
