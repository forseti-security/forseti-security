#!/bin/sh
BASEDIR=$(dirname "$0")
pushd "${BASEDIR}"
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. *.proto
popd
