#!/bin/sh
BASEDIR=$(dirname "$0")
cd "${BASEDIR}"
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. explain.proto
