# SScan version
VERSION=$(shell cat conf/banner.go |grep "const Version ="|cut -d"\"" -f2)
# Output File Location
DIR=data/v${VERSION}
$(shell mkdir -p ${DIR})

# Go build flags
LDFLAGS=-ldflags '--extldflags "-static"'

default:
	go build ${LDFLAGS} -o ${DIR}/Jie main.go

debug:
	go build -o ${DIR}/Jie main.go

# Compile Server - Windows x64
windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/Jie-Windows-x64.exe main.go

# Compile Server - Linux x64
linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/Jie-Linux-x64 main.go

# Compile Server - Darwin x64
darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/Jie-Darwin-x64 main.go

# clean
clean:
	rm -rf ${DIR}