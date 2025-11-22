
VerusCoin Command Line Tools v1.2.12-2

Contents:
verusd - VerusCoin daemon.
verus - VerusCoin command line utility.
fetch_params.sh - utility to download the zcash parameters needed to start the VerusCoin command line tools and scripts
lib*.dylib - assorted dynamic libraries, dependencies needed by fetch-params.sh, verusd and/or verus

Command line tools are run from the terminal. You can launch the terminal on a Mac by using the Finder, selecting Applications and from that select Utilities, finally selecting Terminal from the Utilities folder.
You will need to switch to the directory you extracted the verus-cl into. If you extracted it in the Download folder then the change directory command is
cd ~/Downloads/verus-cli
The first time on a new system you will need to run ./fetch-params before using verusd.

Run:
./verusd to launch the VerusCoin daemon
Use verus to run commands such as:
./verus stop
Which signals verusd (if it is running) to stop running.

