#!/bin/bash

die() { echo "$@" 1>&2 ; exit 1; }

echo "Checking preconditions"
which go || die "Go not found"
which git || die "Git not found"
test -z ${PROTOC} && die "Must define PROTOC environment variable"

BUILD_DIR="../build/"
mkdir -p $BUILD_DIR
BASEDIR=$(dirname "$0")
pushd ${BASEDIR}
PROXYDIR=$(pwd)
popd

pushd ${BASEDIR}/${BUILD_DIR}
PWD=$(pwd)

export GOPATH=$PWD
export PATH=$PATH:$GOPATH/bin

echo "Installing go dependencies"
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
go get -u github.com/golang/protobuf/protoc-gen-go
go get -u golang.org/x/net/context
go get -u google.golang.org/grpc

echo "Installing protobuf dependency"
git clone https://github.com/google/protobuf

PROTOFILES=("google/cloud/security/iam/playground/playground.proto" "google/cloud/security/iam/explain/explain.proto")

for PROTOFILE in ${PROTOFILES[@]}
do

echo "Generating gateway for ${PROTOFILE}"

GRPCDIR=${GOPATH}/src/$(dirname $PROTOFILE)
PROTOFILE="../${PROTOFILE}"

mkdir -p ${GRPCDIR}

echo "Generating gRPC stub"
${PROTOC} -I/usr/local/include -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --go_out=plugins=grpc:${GRPCDIR} \
    ${PROTOFILE}

echo "Generating reverse proxy code"
${PROTOC} -I/usr/local/include -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --grpc-gateway_out=logtostderr=true:${GRPCDIR} \
    ${PROTOFILE}

echo "Generating python code"
python -m grpc_tools.protoc \
    -I. \
    -I$GOPATH/src \
    -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
    -I$(dirname ${PROTOFILE}) \
    -I${PWD}/protobuf/src/ \
    --python_out=$(dirname ${PROTOFILE})\
    --grpc_python_out=$(dirname ${PROTOFILE})\
    ${PROTOFILE}

done # LOOP END

echo "Compiling proxy"
go build src/google/proxy.go


echo "Generating annotations.proto and http.proto"
mkdir -p ../google/api/
cp ${PROXYDIR}/__init__.py ../google/api/

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

