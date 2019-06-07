## VerusCoin version 0.6+ unstable PBaaS branch

This branch cannot yet be expected to work, but it may.

Arguably the world's most advanced technology, zero knowledge privacy-centric blockchain, Verus Coin brings Sapling performance and zero knowledge features to an intelligent system with interchain smart contracts and a completely original, combined proof of stake/proof of work consensus algorithm that solves the nothing at stake problem. With this and its approach towards CPU mining and ASICs, Verus Coin strives to be one of the most naturally decentralizing and attack resistant blockchains in existence.

We have added a variation of a zawy12, lwma difficulty algorithm, a new CPU-optimized hash algorithm and a new algorithm for fair proof of stake. We describe these changes and vision going forward in a [our Phase I white paper](http://185.25.51.16/papers/VerusPhaseI.pdf) and [our Vision](http://185.25.51.16/papers/VerusVision.pdf).

Also see our [VerusCoin web site](https://veruscoin.io/) and [VerusCoin Explorer](https://explorer.veruscoin.io/).

## VerusCoin
This software is the VerusCoin enhanced Komodo client. Generally, you will use this if you want to mine VRSC or setup a full node. When you run the wallet it launches komodod automatically. On first launch it downloads Zcash parameters, roughly 1GB, which is mildly slow.

The wallet downloads and stores the block chain or asset chain of the coin you select. It downloads and stores the entire history of the coins transactions; depending on the speed of your computer and network connection, the synchronization process could take a day or more once the blockchain has reached a significant size.

## Development Resources
- VerusCoin:[https://veruscoin.io/](https://veruscoin.io/) Wallets and CLI tools
- Komodo Web: [https://komodoplatform.com/](https://komodoplatform.com/)
- Organization web: [https://komodoplatform.com/](https://komodoplatform.com/)
- Forum: [https://forum.komodoplatform.com/](https://forum.komodoplatform.com/)
- Mail: [info@komodoplatform.com](mailto:info@komodoplatform.com)
- Support: [https://support.komodoplatform.com/support/home](https://support.komodoplatform.com/support/home)
- Knowledgebase & How-to: [https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages](https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages)
- API references: [http://docs.komodoplatform.com/](http://docs.komodoplatform.com/)
- Blog: [http://blog.komodoplatform.com/](http://blog.komodoplatform.com/)
- Whitepaper: [Komodo Whitepaper](https://komodoplatform.com/wp-content/uploads/2018/03/2018-03-12-Komodo-White-Paper-Full.pdf)
- Komodo Platform public material: [Komodo Platform public material](https://docs.google.com/document/d/1AbhWrtagu4vYdkl-vsWz-HSNyNvK-W-ZasHCqe7CZy0)

## List of Komodo Platform Technologies

- Delayed Proof of Work (dPoW) - Additional security layer and Komodos own consensus algorithm.
- zk-SNARKs - Komodo Platform's privacy technology for shielded transactions
- Tokens/Assets Technology - create "colored coins" on the Komodo Platform and use them as a layer for securites
- Reward API - Komodo CC technology for securities
- CC - Crypto Conditions to realize "smart contract" logic on top of the Komodo Platform
- Jumblr - Decentralized tumbler for KMD and other cryptocurrencies
- Assetchains - Create your own Blockchain that inherits all Komodo Platform functionalities and blockchain interoperability
- Pegged Assets - Chains that maintain a peg to fiat currencies
- Peerchains - Scalability solution where sibling chains form a network of blockchains
- More in depth covered [here](https://docs.google.com/document/d/1AbhWrtagu4vYdkl-vsWz-HSNyNvK-W-ZasHCqe7CZy0)
- Also note you receive 5% APR on your holdings.
[See this article for more details](https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages/20480015/Claim+KMD+Interest+in+Agama)

## Tech Specification
- Launch Date May 21, 2018
- Max Supply: 83,540,184 VRSC
- Block Time: 1M
- Block Reward: variable 24 on December 20, 2018
- Mining Algorithm: VerusHash 2.0
- Consensus 50% PoW, 50% PoS
- Transaction Fee 0.0001
- Privacy: Zcash Sprout
- Komodo Platform with dPOW
- CheatCatcher distributed stake cheating detector

## About this Project
VerusCoin is based on Komodo which is based on Zcash and has been extended by our innovative consensus staking and mining algorithms and a novel 50% PoW/50% PoS approach.

Many VRSC innovations are now also available back in the Komodo fork:
- Eras
- Timelocking
- VerusHash
- VerusPoS
- 50% PoS/50% PoW
 
 More details including a link to our vision and white papers and client downloads are [available on our web site](https://veruscoin.io)

## Getting started

### Dependencies

```shell
#The following packages are needed:
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git python python-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils automake curl
```


Building
--------

First time you'll need to get assorted startup values downloaded. This takes a moderate amount of time once but then does not need to be repeated unless you bring a new system up. The command is:
```
zcutil/fetch-params.sh
```
Building for Ubuntu/Mint/Debian:
```
zcutil/build.sh
```
Building for Mac OS/X (see README-MAC.md):
```
zcutil/build-mac.sh
```
Building for Windows:
```
zcutil/build-win.sh
```
VerusCoin
------
We develop on dev and some other branches and produce releases of of the master branch, using pull requests to manage what goes into master. The dev branch is considered the bleeding edge codebase, and may even be oncompatible from time to time, while the master-branch is considered tested (unit tests, runtime tests, functionality). At no point of time do the Komodo Platform developers or Verus Developers take any responsibility for any damage out of the usage of this software. 

Verus builds for all operating systems out of the same codebase. Follow the OS specific instructions from below.

#### Linux
```shell
git clone https://github.com/VerusCoin/VerusCoin
cd VerusCoin
#you might want to: git checkout <branch>; git pull
./zcutil/fetch-params.sh
# -j8 = using 8 threads for the compilation - replace 8 with number of threads you want to use
./zcutil/build.sh -j8
#This can take some time.
```

**The VerusCoin enhanced komodo is experimental and a work-in-progress.** Use at your own risk.

#To view all commands
./src/komodo-cli help

#To view komodod output:
tail -f ~/.komodo/debug.log
#To view VRSC output:
tail -f ~/.komodo/VRSC/debug.log
Note that this directory is correct for Linux, not Mac or Windows. Coin info for Verus is stored in ~/.komodo/VRSC under Ubuntu/Linux.

For Windows coin info for Verus is stored under \Users<username>\AppData\Roaming\Komodo\VRSC

For Mac coin info for Verus is stored under ~/Library/Application\ Support/Komodo/VRSC

**Zcash is unfinished and highly experimental.** Use at your own risk.

Always back your wallets up carefully and securely, **especially before attempting the following process**

In some cases, messed up wallets can be recovered using this process
 
- backup wallet.dat safely and securely
- backup all privkeys (launch komodod with `-exportdir=<path>` and `dumpwallet`)
- start a totally new sync including `wallet.dat`, launch with same `exportdir`
- stop it before it gets too far and import all the privkeys from a) using `komodo-cli importwallet filename`
- resume sync till it gets to chaintip

For example:
```shell
./verusd -exportdir=/tmp &
./verus dumpwallet example
./verus stop
mv ~/.komodo/VRSC ~/.komodo/VRSC.old && mkdir ~/.komodo/VRSC && cp ~/.komodo/VRSC.old/VRSC.conf ~/.komodo/VRSC.old/peers.dat ~/.komodo/VRSC
./verusd -exchange -exportdir=/tmp &
./verus importwallet /tmp/example
```
---


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notices and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

