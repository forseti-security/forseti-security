FROM ubuntu:14.04

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
RUN pip install --upgrade coveralls coverage pylint grpcio grpcio-tools protobuf mock

ADD . /forseti-security/
WORKDIR /forseti-security/
RUN PYTHONPATH=. python setup.py install
RUN yes | pip uninstall -q forseti-security

#RUN coverage run --source='google.cloud.security' --omit='__init__.py' -m unittest discover -s . -p "*_test.py" || echo "anyway"
#RUN coverage report
