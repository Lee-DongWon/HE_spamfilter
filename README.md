# HE Spamfilter
**SNUCSE 2021 "Intelligent Computing System Design Project"**

* Hyesun Kwak
* Myeonghwan Ahn
* Dongwon Lee

## abstract
* Naïve Bayesian spam filtering
* with Homomorphic Encryption (using [Lattigo](https://github.com/ldsec/lattigo) implementation of CKKS)
* with [BERT embedding](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/main/tokenizer.json) (using [huggingface/tokenizers](https://github.com/huggingface/tokenizers))
* on `enron` dataset from [MWiechmann/enron_spam_data](https://github.com/MWiechmann/enron_spam_data)
* using [gin](https://github.com/gin-gonic/gin) web framework


## tested on
* client (both sender & receiver)
    * MacBook Air (M1, 2020)
    * macOS 12.0.1 (21A559)
    * Docker Desktop 4.3.0 (71786)
        * `go version go1.13.8 linux/arm64`
* server
    * [intel Xeon Platinum 8268](https://ark.intel.com/content/www/kr/ko/ark/products/192481/intel-xeon-platinum-8268-processor-35-75m-cache-2-90-ghz.html)
    * ~200 GiB memory
    * Ubuntu 20.04.3 LTS
        * `go version go1.13.8 linux/amd64`
* common
    * [Lattigo v2.3.0](https://github.com/ldsec/lattigo/releases/tag/v2.3.0)
    * [huggingface/tokenizers v0.11.0](https://github.com/huggingface/tokenizers/releases/tag/python-v0.11.0)


## how it works
1. receiver
    * generates keys
    * posts its public key-set on server
        * public key `pk`, relinearization key `rek`, rotation key `rok`
2. sender
    * writes down some letter
    * in demo, random sample from `enron` dataset
    * tokenizes the letter
    * in demo, use already-tokenized value from `enron` dataset
    * make it one-or-zero(occur in letter or not) per embedding
    * gets public key from server
    * encrypt one-or-zero embedding
    * post result on server
3. receiver
    * get result from server
    * decrypt using secret key

## how to run
NOTE that we made some update on `ckks/params.go`; see `sender/setup.sh:17` and `sender/params.go`

### server
`cd your_path_to/HE_spamfilter/server`

* install some golang dependency on `main.go`
* you need to handle some nasty `PATH` problem... see `sender/setup.sh:11~16`

`cp ../sender/params.go your_GOPATH/src/github.com/ldsec/lattigo/v2/ckks/params.go`

`go run main.go`

### client - sender
`cd your_path_to/HE_spamfilter/sender`
* on linux, `tar -zxvf enron.tar.gz`
* on mac, `gtar -zxvf enron.tar.gz`
    * install GNU-tar using [brew](https://brew.sh)
    * `brew update && brew install gnu-tar`

`docker run -it -v your_path_to/HE_spamfilter/sender:/home --rm ubuntu:focal`

in container shell,
`cd /home`
`bash setup.sh`

### client - receiver
`docker run -it -v your_path_to/HE_spamfilter/receiver:/home --rm ubuntu:focal`

in container shell,
`cd /home`
`bash setup.sh`

### demo
with server & two client containers running,
* receiver  `python3 demo_keygen.py`
* sender    `python3 demo_send.py`
* receiver  `python3 demo_rcv.py`


## result
* accuracy
    * accuracy 0.96391
    * F1 score 0.96197
* latency
    * key post
        * public key (9.1 M) : 2.48 s
        * relinearization key (289 M) : 75 s
        * rotation key (289 M) : 52.87 s
        * by the way, secret key size is 4.6 M
    * key get
        * public key : 432.244 ms
    * message post
        * select random 10
        * POST + HE calculation + some filesystem access time
        * encrypted message : 5.1 M each
        * [1.878, 2.225, 1.636, 2.372, 1.838, 2.232, 1.860, 1.864, 1.839, 3.666] s
    * message get
        * calculation result : 5.1 M each
        * [167, 86, 103, 184, 81, 104, 299, 272, 96, 119] ms

## about dataset
[MWiechmann/enron_spam_data](https://github.com/MWiechmann/enron_spam_data) provides `enron_spam_data.csv`

We corrected some format error on that to make `enron_spam_data_prep.csv`, which consists of 33715 e-mails (16545 ham + 17170 spam)
