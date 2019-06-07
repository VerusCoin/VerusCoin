#!/bin/sh

DIST_DIR=verus-cli
mkdir ${DIST_DIR}

cp src/fiat/verus \
   src/verusd \
   doc/man/verus-cli/mac/README.txt \
   zcutil/fetch-params.sh \
   verus-cli
mv verus-cli/fetch-params.sh verus-cli/fetch-params
chmod +x ${DIST_DIR}/fetch-params
chmod +x ${DIST_DIR}/verus
chmod +x ${DIST_DIR}/verusd

binaries=("verus" "verusd")
alllibs=()
for binary in "${binaries[@]}";
do
    # do the work in the destination directory
    cp src/${binary} ${DIST_DIR}
    # find the dylibs to copy for verusd
    DYLIBS=`otool -L ${DIST_DIR}/${binary} | grep "/usr/local" | awk -F' ' '{ print $1 }'`
    DYLIBS+=" /usr/local/opt/libidn2/lib/libidn2.0.dylib"
    echo "copying ${DYLIBS} to ${DIST_DIR}"
    # copy the dylibs to the srcdir
    for dylib in ${DYLIBS}; do cp -rf ${dylib} ${DIST_DIR}; done
done

libraries=("libgcc_s.1.dylib" "libgomp.1.dylib" "libidn2.0.dylib" "libstdc++.6.dylib")

for binary in "${libraries[@]}";
do
    # find the dylibs to copy for verusd
    DYLIBS=`otool -L ${DIST_DIR}/${binary} | grep "/usr/local" | awk -F' ' '{ print $1 }'`
    echo "copying ${DYLIBS} to ${DIST_DIR}"
    # copy the dylibs to the srcdir
    for dylib in ${DYLIBS}; do cp -rf ${dylib} ${DIST_DIR}; alllibs+=(${dylib}); done
done

indirectlibraries=("libintl.8.dylib" "libunistring.2.dylib")

for binary in "${indirectlibraries[@]}";
do
    # Need to undo this for the dylibs when we are done
    chmod 755 ${DIST_DIR}/${binary}
    # find the dylibs to copy for verusd
    DYLIBS=`otool -L ${DIST_DIR}/${binary} | grep "/usr/local" | awk -F' ' '{ print $1 }'`
    echo "copying indirect ${DYLIBS} to ${DIST_DIR}"
    # copy the dylibs to the dest dir
    for dylib in ${DYLIBS}; do cp -rf ${dylib} ${DIST_DIR}; alllibs+=(${dylib}); done
done

for binary in "${binaries[@]}";
do
    # modify verusd to point to dylibs
    echo "modifying ${binary} to use local libraries"
    for dylib in "${alllibs[@]}"
    do
        echo "Next lib is ${dylib} "
        install_name_tool -change ${dylib} @executable_path/`basename ${dylib}` ${DIST_DIR}/${binary}
    done
    chmod +x ${DIST_DIR}/${binary}
done

for binary in "${libraries[@]}";
do
    # modify libraries to point to dylibs
    echo "modifying ${binary} to use local libraries"
    for dylib in "${alllibs[@]}"
    do
        echo "Next lib is ${dylib} "
        install_name_tool -change ${dylib} @executable_path/`basename ${dylib}` ${DIST_DIR}/${binary}
    done
done

