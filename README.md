HoneyBadger
===========

<img src="https://github.com/christoftorres/HoneyBadger/blob/master/honeybadger_logo.png" width="200">

An analysis tool to detect honeypots in Ethereum smart contracts :honey_pot:. HoneyBadger is based on [Oyente](https://github.com/melonproject/oyente).

## Quick Start

A container with the dependencies set up can be found [here](https://hub.docker.com/r/christoftorres/honeybadger/).

To open the container, install docker and run:

```
docker pull christoftorres/honeybadger && docker run -i -t christoftorres/honeybadger
```

To evaluate a simple honeypot inside the container, run:

```
python honeybadger/honeybadger.py -s honeypots/MultiplicatorX3.sol
```

and you are done!

## Custom Docker image build

```
docker build -t honeybadger .
docker run -it honeybadger:latest
```

## Full installation

### Install the following dependencies
#### solc
```
$ sudo add-apt-repository ppa:ethereum/ethereum
$ sudo apt-get update
$ sudo apt-get install solc
```

#### evm from [go-ethereum](https://github.com/ethereum/go-ethereum)

1. https://geth.ethereum.org/downloads/ or
2. By from PPA if your using Ubuntu
```
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository -y ppa:ethereum/ethereum
$ sudo apt-get update
$ sudo apt-get install ethereum
```

#### [z3](https://github.com/Z3Prover/z3/releases) Theorem Prover version 4.7.1.

Download the [source code of version z3-4.7.1](https://github.com/Z3Prover/z3/releases/tag/z3-4.7.1)

Install z3 using Python bindings

```
$ python scripts/mk_make.py --python
$ cd build
$ make
$ sudo make install
```

#### [Requests](https://github.com/kennethreitz/requests/) library

```
pip install requests
```

#### [web3](https://github.com/pipermerriam/web3.py) library

```
pip install web3
```

### Evaluate Ethereum smart contract honeypot

```
python honeybadger.py -s <contract filename>
```

Run ```python honeybadger.py --help``` for a complete list of options.
