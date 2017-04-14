#!/bin/bash

BASEDIR=$(dirname "$0")
pushd ${BASEDIR}
PWD=$(pwd)

export GOPATH=$PWD
export PATH=$PATH:$GOPATH/bin

go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
go get -u github.com/golang/protobuf/protoc-gen-go

go get -u golang.org/x/net/context
go get -u google.golang.org/grpc

git clone https://github.com/google/protobuf

PROTOFILE="../google/cloud/security/iam/playground/playground.proto"
PROXYDIR=$(pwd)/src/google/cloud/security/iam/playground/

mkdir -p ${PROXYDIR}

# Generate gRPC stub
protoc -I/usr/local/include -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --go_out=plugins=grpc:${PROXYDIR} \
    ${PROTOFILE}

# Generate reverse proxy
protoc -I/usr/local/include -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --grpc-gateway_out=logtostderr=true:${PROXYDIR} \
    ${PROTOFILE}

# Generate python code
python -m grpc_tools.protoc \
    -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --python_out=$(dirname ${PROTOFILE})\
    --grpc_python_out=$(dirname ${PROTOFILE})\
    ${PROTOFILE}

go build src/google/proxy.go


mkdir -p ../google/api/
cp __init__.py ../google/api/

python -m grpc_tools.protoc \
    -I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    --python_out=../google/api \
    --grpc_python_out=../google/api \
    ${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api/annotations.proto

python -m grpc_tools.protoc \
    -I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    --python_out=../google/api \
    --grpc_python_out=../google/api \
    ${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api/http.proto

popd

