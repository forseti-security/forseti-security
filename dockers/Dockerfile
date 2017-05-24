FROM ubuntu:16.04

# Install Forseti dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    libmysqlclient-dev \
    python-pip \
    python-dev \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip
RUN pip install --upgrade coveralls coverage pylint grpcio grpcio-tools protobuf
