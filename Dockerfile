FROM ubuntu:16.04

# Install Forseti dependencies
RUN apt-get update && apt-get install -qq -y \
    curl \
    git \
    libmysqlclient-dev \
    python-pip \
    python-dev \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

RUN pip install -q --upgrade pip
RUN pip install -q --upgrade \
    coverage \
    coveralls \
    google-apputils \
    grpcio \
    grpcio-tools \
    mock \
    pylint

ADD . /forseti-security/
WORKDIR /forseti-security/
RUN python setup.py install
