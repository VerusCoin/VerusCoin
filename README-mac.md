The build was tested in the following environment: `macOS Monterey 12.6.1`.

```bash
sw_vers && xcodebuild -version && clang --version
...
ProductName:		macOS
ProductVersion:		13.4
BuildVersion:		22F66
Xcode 14.3.1
Build version 14E300c
Apple clang version 14.0.3 (clang-1403.0.22.14.1)
Target: x86_64-apple-darwin22.5.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
```

#### OSX (Native)
Ensure you have [brew](https://brew.sh) and Command Line Tools installed.
```shell
# Install brew
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
# Install Xcode, opens a pop-up window to install CLT without installing the entire Xcode package
xcode-select --install 
# Update brew and install dependencies
brew update
brew upgrade
brew tap discoteq/discoteq; brew install flock
brew install autoconf autogen automake
brew install binutils
brew install protobuf
brew install coreutils
brew install wget


Get all that installed, then run:

```shell
git clone https://github.com/VerusCoin/VerusCoin.git
cd VerusCoin
./zcutil/fetch-params.sh
```

For x86 macs:
```
./zcutil/build-mac.sh
```

For Apple silicon:
```
./zcutil/build-mac-arm.sh
```

Happy Building
