
## VerusCoin version 1.2.14

Arguably the world's most advanced technology, zero knowledge privacy enabled, multi-chain blockchain protocol, Verus Public Blockchains as a Service (PBaaS) combines Sapling zero knowledge technology with an intelligent, multi-chain, provable protocol, using interchain smart transactions. Verus PBaaS also enables merge mining and cross-chain staking with a completely original, combined proof of stake/proof of work consensus algorithm, Proof of Power, that can be mined on CPUs and mobile phones, and also solves the nothing at stake problem. With this and its approach towards CPU mining and ASICs, Verus Coin strives to be one of the most naturally decentralizing and attack resistant blockchain networks in existence.

[VerusCoin web site](https://verus.io/) and [VerusCoin Explorer](https://explorer.verus.io/).

[Our Vision](https://verus.io/papers/VerusVision.pdf).

## VerusCoin
This software is the VerusCoin p2p node and client. Generally, you will use this if you want to mine VRSC or setup a full node. When you run the wallet it launches verusd automatically. On first launch it downloads Zcash parameters, roughly 1GB, which is relatively slow.

The daemon downloads and stores the block chain of the PBaaS chain you select on load, using the -chain=<name> parameter. It downloads and stores the entire history of the coins transactions; depending on the speed of your computer and network connection, the synchronization process could take a day or more once the blockchain has reached a significant size.

## Development Resources
- VerusCoin:[https://verus.io/](https://verus.io/) Wallets and CLI tools
- Discord: [https://verus.io/discord](https://verus.io/discord)
- Mail: [development@verus.io](development@verus.io)
- FAQs & How-to: [https://wiki.verus.io/#!index.md](https://wiki.veruscoin.io/#!index.md)
- API references: [https://wiki.verus.io/#!faq-cli/clifaq-02_verus_commands.md](https://wiki.verus.io/#!faq-cli/clifaq-02_verus_commands.md)
- Medium: [https://medium.com/@veruscoin](https://medium.com/@veruscoin)
- Explorer: [https://explorer.verus.io/](https://explorer.verus.io/)
## Tech Specification
- Launch Date May 21, 2018
- Max Supply: 83,540,184 VRSC
- Block Time: 1M
- Block Reward: variable 24 on December 20, 2018
- Mining Algorithm: VerusHash 2.0
- Consensus 50% PoW, 50% PoS
- Transaction Fee 0.0001
- Privacy: Zcash Sapling
- dPOW on Komodo blockchain
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
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git zlib1g-dev wget bsdmainutils automake curl
```

ARMv8 cross-compile
```shell
#The following packages are needed:
sudo apt-get install build-essential pkg-config linux-libc-dev-arm64-cross m4 autoconf g++-aarch64-linux-gnu binutils-aarch64-linux-gnu libtool ncurses-dev unzip git zlib1g-dev wget bsdmainutils automake curl
```
Windows cross-compile
```shell
#The following packages are needed:
sudo apt-get install autoconf automake autogen bsdmainutils cmake curl git libc6-dev libcap-dev libdb++-dev libqrencode-dev libprotobuf-dev libssl-dev libtool libz-dev libbz2-dev m4 make mingw-w64 ncurses-dev pkg-config protobuf-compiler unzip wget zip zlib1g-dev 
```

Building
--------

First time you'll need to get assorted startup values downloaded. This takes a moderate amount of time once but then does not need to be repeated unless you bring a new system up. The command is:
```
zcutil/fetch-params.sh
```
Building for Linux:
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
We develop on dev and some other branches and produce releases of of the master branch, using pull requests to manage what goes into master. The dev branch is considered the bleeding edge codebase, and may even be incompatible from time to time, while the master-branch is considered tested (unit tests, runtime tests, functionality). At no point of time do the Komodo Platform developers or Verus Developers take any responsibility for any damage out of the usage of this software. 

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
#### Linux ARMv8 Cross-compile
```shell
git clone https://github.com/VerusCoin/VerusCoin
cd VerusCoin
#you might want to: git checkout <branch>; git pull
./zcutil/fetch-params.sh
# -j8 = using 8 threads for the compilation - replace 8 with number of threads you want to use
HOST= aarch64-linux-gnu ./zcutil/build.sh -j8
#This can take some time.
```

#To view all commands
./src/verus help

#To view verusd debug output:
```
tail -f ~/.komodo/VRSC/debug.log
```
Note that this directory is correct for Linux, not Mac or Windows. Coin info for Verus is stored in ~/.komodo/VRSC under Ubuntu/Linux.

For Windows coin info for Verus is stored under \Users<username>\AppData\Roaming\Komodo\VRSC

For Mac coin info for Verus is stored under ~/Library/Application\ Support/Komodo/VRSC

**The VerusCoin project and protocol is experimental and a work-in-progress.** Use this source code and software at your own risk.

Always back your wallets up carefully and securely, **especially before attempting the following process**

In some cases, messed up wallets can be recovered using this process
 
- backup wallet.dat safely and securely
- backup all privkeys (launch komodod with `-exportdir=<path>` and `dumpwallet`)
- start a totally new sync including `wallet.dat`, launch with same `exportdir`
- stop it before it gets too far and import all the privkeys from a) using `verus importwallet filename`
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

