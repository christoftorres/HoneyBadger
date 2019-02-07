FROM ubuntu:16.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update
RUN apt-get install -y sudo wget tar unzip pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update

# Install z3
RUN wget https://github.com/Z3Prover/z3/releases/download/z3-4.7.1/z3-4.7.1-x64-ubuntu-16.04.zip && unzip z3-4.7.1-x64-ubuntu-16.04.zip && rm z3-4.7.1-x64-ubuntu-16.04.zip && mv z3-4.7.1-x64-ubuntu-16.04/bin/* /usr/local/bin && rm -r z3-4.7.1-x64-ubuntu-16.04
# Install solidity
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.25/solidity_0.4.25.tar.gz && tar -xvzf solidity_0.4.25.tar.gz && rm solidity_0.4.25.tar.gz && cd solidity_0.4.25 && ./scripts/install_deps.sh && ./scripts/build.sh && cd .. && rm -r solidity_0.4.25
# Install go
RUN wget https://storage.googleapis.com/golang/go1.9.2.linux-amd64.tar.gz && tar -xvf go1.9.2.linux-amd64.tar.gz && rm go1.9.2.linux-amd64.tar.gz && cp go/bin/* /usr/local/bin && mv go /usr/local && mkdir -p ~/go; echo "export GOPATH=$HOME/go" >> ~/.bashrc && echo "export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin" >> ~/.bashrc && source ~/.bashrc
# Install geth
RUN wget https://github.com/ethereum/go-ethereum/archive/v1.8.16.zip && unzip v1.8.16.zip && rm v1.8.16.zip && cd go-ethereum-1.8.16 && make all && mv build/bin/* /usr/local/bin && cd .. && rm -r go-ethereum-1.8.16
# Create virtualenv
RUN virtualenv venv && source venv/bin/activate
# Upgrade pip
RUN pip install --upgrade pip setuptools wheel
# Install requests
RUN pip install requests
# Install web3
RUN pip install web3==0.1.9

WORKDIR /root
COPY datasets/honeypots honeypots
COPY honeybadger honeybadger
