# SScan version
VERSION=$(shell cat conf/banner.go |grep "const Version ="|cut -d"\"" -f2)
# Output File Location
DIR=data/v${VERSION}
$(shell mkdir -p ${DIR})
# go build flags 删除符号表和调试信息，减小生成文件的大小
LDFLAGS=-ldflags "-s -w"

default:
	export CGO_ENABLED=1;go build ${LDFLAGS} -o ${DIR}/Jie main.go

# 会在程序奔溃时生成 coredump 文件，可以使用 https://github.com/go-delve/delve 工具调试
debug:
	export CGO_ENABLED=1;go build -o ${DIR}/Jie main.go; ulimit -c unlimited; export GOTRACEBACK=crash

# clean
clean:
	rm -rf ${DIR}