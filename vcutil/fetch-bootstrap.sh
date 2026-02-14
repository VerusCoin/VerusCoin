#!/bin/bash
trap '[[ -z "$(jobs -p)" ]] || kill $(jobs -p)' EXIT

set -eu

function set_data_dir() {
  echo Enter blockchain data directory or leave blank for default:
  read -r vrsc_data_dir
  if [[ "$vrsc_data_dir" == "" ]]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      V_CHAIN_DATA_DIR="$HOME/Library/Application Support/Komodo/VRSC"
    else
      V_CHAIN_DATA_DIR="$HOME/.komodo/VRSC"
    fi
  else
    V_CHAIN_DATA_DIR="$vrsc_data_dir"
  fi
  echo -n "Install bootstrap in ${V_CHAIN_DATA_DIR}? ([1]Yes/[2]No)"
  read -r answer
  if [ "$answer" != "${answer#[1]}" ]; then
    echo
  else
    echo bootstrap not installed
    exit 1
  fi
}

BOOTSTRAP_URL="https://bootstrap.verus.io"
BOOTSTRAP_ARCHIVE="VRSC-bootstrap.tar.gz"
BOOTSTRAP_ARCHIVE_SIG="$BOOTSTRAP_ARCHIVE.verusid"
SHA256CMD="$(command -v sha256sum || echo shasum)"
SHA256ARGS="$(command -v sha256sum >/dev/null || echo '-a 256')"

WGETCMD="$(command -v wget || echo '')"
IPFSCMD="$(command -v ipfs || echo '')"
CURLCMD="$(command -v curl || echo '')"
PIDOFCMD="$(command -v pidof || echo '')"
PGREPCMD="$(command -v curl || echo '')"
PROCESS_RUNNING=

# fetch methods can be disabled with ZC_DISABLE_SOMETHING=1
ZC_DISABLE_WGET="${ZC_DISABLE_WGET:-}"
ZC_DISABLE_IPFS="${ZC_DISABLE_IPFS:-}"
ZC_DISABLE_CURL="${ZC_DISABLE_CURL:-}"

# overwrite chain data if found
OVERWRITE_BLOCKCHAIN_DATA="${OVERWRITE_BLOCKCHAIN_DATA:-}"

function check_pidof() {
  if [ -z "${PIDOFCMD}" ]; then
    return 1
  fi
  local processname="$1"
  cat <<EOF

Checking if $processname is running
EOF

  pidof "${processname}" >/dev/null
  # Check the exit code of the shasum command:
  PIDOF_RESULT=$?
  if [ $PIDOF_RESULT -eq 0 ]; then
    PROCESS_RUNNING=1
  fi
}

function check_pgrep() {
  if [ -z "${PGREPCMD}" ]; then
    return 1
  fi
  local processname="$1"
  cat <<EOF

Checking if $processname is running
EOF

  pgrep -x "${processname}" >/dev/null
  # Check the exit code of the shasum command:
  PGREP_RESULT=$?
  if [ $PGREP_RESULT -eq 0 ]; then
    PROCESS_RUNNING=1
  fi
}

function check_failure() {
  cat >&2 <<EOF

Make sure to have either pidof or pgrep installed on your system

EOF
  exit 1
}
function fetch_wget() {
  if [ -z "$WGETCMD" ] || [ -n "$ZC_DISABLE_WGET" ]; then
    return 1
  fi

  local filename="$1"
  local dlname="$2"
  local url="$3"

  cat <<EOF

Retrieving (wget): ${url}/${filename}
EOF

  wget \
    --progress=dot:giga \
    --output-document="${dlname}" \
    --continue \
    --retry-connrefused --waitretry=3 --timeout=30 \
    "${url}/${filename}"
}

function fetch_ipfs() {
  if [ -z "${IPFSCMD}" ] || [ -n "${ZC_DISABLE_IPFS}" ]; then
    return 1
  fi

  local filename="$1"
  local dlname="$2"
  local cid="$3"
  cat <<EOF

Retrieving (ipfs): ${cid}/$filename
EOF

  ipfs get --output "${dlname}" "${cid}/${filename}"
}

function fetch_curl() {
  if [ -z "${CURLCMD}" ] || [ -n "${ZC_DISABLE_CURL}" ]; then
    return 1
  fi

  local filename="$1"
  local dlname="$2"
  local url="$3"
  cat <<EOF

Retrieving (curl): ${url}/${filename}
EOF

  curl \
    --output "${dlname}" \
    -# -L -C - \
    "${url}/${filename}"

}

function fetch_failure() {
  cat >&2 <<EOF

Failed to fetch data bootstrap
Make sure  one of the following programs installed and make sure you're online:

 * ipfs
 * wget
 * curl

EOF
  exit 1
}

function verify_checksum() {
  local filename="$1"
  local dlname="$2"
  local expectedhash="$3"
  cat <<EOF

Verifying $filename checksum
EOF
  "$SHA256CMD" $SHA256ARGS -c <<EOF
$expectedhash  $dlname
EOF
}

# Use flock to prevent parallel execution.
function lock() {
  local lockfile=/tmp/fetch_bootstrap.lock
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if shlock -f ${lockfile} -p $$; then
      return 0
    else
      return 1
    fi
  else
    # create lock file
    eval "exec 200>$lockfile"
    # acquire the lock
    flock -n 200 &&
      return 0 ||
      return 1
  fi
}

function exit_locked_error() {
  echo "Only one instance of fetch-bootstrap.sh can be run at a time." >&2
  exit 1
}

function overwrite_bootstrap_data() {
  for method in pgrep pidof failure; do
    if "check_$method" verusd; then
      if [ -z "$PROCESS_RUNNING" ]; then
        for item in "${vrsc_data[@]}"; do
          echo "Removing ${item}"
          rm -rf "${item}"
        done
      else
        echo Verusd is running, close and try again.
        exit 1
      fi
      break
    fi
  done
}

function fetch_bootstrap() {
  echo Fetching bootstrap
  for method in wget curl failure; do
    if "fetch_$method" "$BOOTSTRAP_ARCHIVE" "/tmp/$BOOTSTRAP_ARCHIVE" "${BOOTSTRAP_URL}"; then
      echo "Download successful!"
      break
    fi
  done

  for method in wget curl failure; do
    if "fetch_$method" "$BOOTSTRAP_ARCHIVE_SIG" "/tmp/$BOOTSTRAP_ARCHIVE_SIG" "${BOOTSTRAP_URL}"; then
      echo "Download successful!"
      break
    fi
  done

  expectedhash="$(awk -F'[, \t]*' '/hash/{print substr($3,2,length($3)-2)}' /tmp/$BOOTSTRAP_ARCHIVE_SIG)"
  if verify_checksum $BOOTSTRAP_ARCHIVE_SIG /tmp/$BOOTSTRAP_ARCHIVE "$expectedhash"; then
    echo Extracting bootstrap
    tar -xzf "/tmp/$BOOTSTRAP_ARCHIVE" --directory "${V_CHAIN_DATA_DIR}"
    echo Bootstrap successfully installed
    rm /tmp/$BOOTSTRAP_ARCHIVE_SIG
    rm /tmp/$BOOTSTRAP_ARCHIVE
  else
    echo "Failed to verify bootstrap checksum!" >&2
    rm /tmp/$BOOTSTRAP_ARCHIVE_SIG
    rm /tmp/$BOOTSTRAP_ARCHIVE
  fi
}

function main() {
  lock fetch-bootstrap.sh ||
    exit_locked_error
  cat <<EOF

This script will install a blockchain data bootstrap

EOF
  # set chain data dir
  if [[ -z "${V_CHAIN_DATA_DIR-}" ]]; then
    set_data_dir
  fi
  data_files=("fee_estimates.dat" "komodostate" "komodostate.ind" "peers.dat" "db.log" "debug.log" "signedmasks")
  data_dirs=("blocks" "chainstate" "database")
  vrsc_data=()
  if ! [ -d "${V_CHAIN_DATA_DIR}" ]; then
    echo "making dir ${V_CHAIN_DATA_DIR}"
    mkdir -p "${V_CHAIN_DATA_DIR}"
  else
    for file in "${data_files[@]}"; do
      if [ -f "${V_CHAIN_DATA_DIR}/${file}" ]; then
        vrsc_data+=("${V_CHAIN_DATA_DIR}"/"${file}")
      fi
    done

    for dir in "${data_dirs[@]}"; do
      if [ -d "${V_CHAIN_DATA_DIR}/${dir}" ]; then
        vrsc_data+=("${V_CHAIN_DATA_DIR}"/"${dir}")
      fi
    done
  fi
  if [ ${#vrsc_data[*]} -lt 1 ]; then
    cd "${V_CHAIN_DATA_DIR}"
    echo Fetching bootstrap
    fetch_bootstrap
  else
    echo "Found existing VRSC data:"
    echo "####################################################################################"
    for item in "${vrsc_data[@]}"; do
      echo "${item}"
    done
    echo "####################################################################################"
    if [ -n "$OVERWRITE_BLOCKCHAIN_DATA" ]; then
      overwrite_bootstrap_data
      fetch_bootstrap
    else
      echo -n "Existing blockchain data found. Overwrite? ([1]Yes/[2]No)"
      read -r answer
      if [ "$answer" != "${answer#[1]}" ]; then
        overwrite_bootstrap_data
        fetch_bootstrap
      else
        echo bootstrap not installed
        exit 1
      fi
    fi
  fi
}
main
rm -f /tmp/fetch_bootstrap
exit 0
