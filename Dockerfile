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
RUN pip install --upgrade coveralls coverage pylint grpcio grpcio-tools protobuf mock google-apputils

ADD . /forseti-security/
WORKDIR /forseti-security/
RUN PYTHONPATH=. python setup.py install
RUN yes | pip uninstall -q forseti-security

