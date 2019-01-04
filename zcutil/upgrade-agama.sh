#!/bin/bash
#set working directory to the location of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Removing old binaries"
    rm /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/verusd/*
    echo "Copying files"
    cp ./* /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/verusd/
    rm /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/verusd/verusd
    mv /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/verusd/komodod /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/verusd/verusd
    echo "Upgrade complete"
else
    echo "Agama directory, followed by [ENTER]:"
    read AGAMA_DIR
    echo "Removing old binaries"
    rm ${AGAMA_DIR}/resources/app/assets/bin/linux64/verusd/*
    echo "Copying files"
    cp ./* ${AGAMA_DIR}/resources/app/assets/bin/linux64/verusd/
    rm ${AGAMA_DIR}/resources/app/assets/bin/linux64/verusd/verusd
    mv ${AGAMA_DIR}/resources/app/assets/bin/linux64/verus/komodod ${AGAMA_DIR}/resources/app/assets/bin/linux64/verusd/verusd
    echo "Upgrade complete"
fi
