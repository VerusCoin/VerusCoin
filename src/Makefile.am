# Copyright (c) 2018-2023 The Verus developers
# Copyright (c) 2017-2019 The Komodo developers
# Copyright (c) 2016-2019 The Zcash developers
# Copyright (c) 2013-2019 The Bitcoin Core developers
# Copyright (c) 2013-2019 Bitcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

DIST_SUBDIRS = secp256k1 univalue cryptoconditions

# AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(SAN_LDFLAGS) $(HARDENED_LDFLAGS) -Wl,--no-as-needed,-lprofiler,--as-needed
# AM_CXXFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS) -Wl,--no-as-needed -lprofiler -Wl,--as-needed
# AM_CPPFLAGS = $(HARDENED_CPPFLAGS) -Wl,--no-as-needed -lprofiler -Wl,--as-needed
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(SAN_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if ARCH_ARM
PLATFORM_VARIANT = armv8.1-a+crypto
else
PLATFORM_VARIANT = x86-64
endif


if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -D__STDC_LIMIT_MACROS"
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/cryptoconditions/include
BITCOIN_INCLUDES += -I$(srcdir)/cryptoconditions/src/include/falcon
BITCOIN_INCLUDES += -I$(srcdir)/cryptoconditions/src
BITCOIN_INCLUDES += -I$(srcdir)/cryptoconditions/src/asn
BITCOIN_INCLUDES += -I$(srcdir)/univalue/include

LIBCURL=-lcurl
LIBBITCOIN_SERVER=libbitcoin_server.a $(LIBCURL) -larchive
LIBBITCOIN_WALLET=libbitcoin_wallet.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CLI=libbitcoin_cli.a
LIBBITCOIN_UTIL=libbitcoin_util.a
LIBBITCOIN_CRYPTO=crypto/libbitcoin_crypto.a
LIBVERUS_CRYPTO=crypto/libverus_crypto.a
LIBVERUS_PORTABLE_CRYPTO=crypto/libverus_portable_crypto.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBCRYPTOCONDITIONS=cryptoconditions/libcryptoconditions_core.la
LIBUNIVALUE=univalue/libunivalue.la
LIBZCASH=libzcash.a
LIBTLS=libtls.a

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif
if ENABLE_PROTON
LIBBITCOIN_PROTON=libbitcoin_proton.a
endif
if BUILD_BITCOIN_LIBS
LIBZCASH_CONSENSUS=libzcashconsensus.la
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F) OPTFLAGS="-O3 -march=$(PLATFORM_VARIANT) -g "

$(LIBUNIVALUE): $(wildcard univalue/lib/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F) OPTFLAGS="-O3 -march=$(PLATFORM_VARIANT) -g "

$(LIBCRYPTOCONDITIONS): $(wildcard cryptoconditions/src/*) $(wildcard cryptoconditions/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F) OPTFLAGS="-O3 -march=$(PLATFORM_VARIANT) -g "

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBVERUS_CRYPTO) \
  $(LIBVERUS_PORTABLE_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
    libzcash.a \
    libtls.a

if ENABLE_WALLET
BITCOIN_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += $(LIBBITCOIN_WALLET)
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += $(LIBBITCOIN_ZMQ)
endif
if ENABLE_PROTON
EXTRA_LIBRARIES += $(LIBBITCOIN_PROTON)
endif

lib_LTLIBRARIES = $(LIBZCASH_CONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =

#if BUILD_BITCOIND
  bin_PROGRAMS += verusd
#endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += verus verus-tx
endif
if ENABLE_WALLET
  bin_PROGRAMS += wallet-utility
endif


LIBZCASH_H = \
  zcash/IncrementalMerkleTree.hpp \
  zcash/NoteEncryption.hpp \
  zcash/Address.hpp \
  zcash/address/sapling.hpp \
  zcash/address/sprout.hpp \
  zcash/address/zip32.h \
  zcash/JoinSplit.hpp \
  zcash/Note.hpp \
  zcash/prf.h \
  zcash/Proof.hpp \
  zcash/util.h \
  zcash/Zcash.h

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  addressindex.h \
  spentindex.h \
  addrman.h \
  alert.h \
  amount.h \
  amqp/amqpabstractnotifier.h \
  amqp/amqpconfig.h \
  amqp/amqpnotificationinterface.h \
  amqp/amqppublishnotifier.h \
  amqp/amqpsender.h \
  arith_uint256.h \
  asyncrpcoperation.h \
  asyncrpcqueue.h \
  base58.h \
  bech32.h \
  bloom.h \
  cc/eval.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/params.h \
  consensus/upgrades.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  crypto/haraka.h \
  crypto/haraka_portable.h \
  crypto/verus_clhash.h \
  crypto/verus_hash.h \
  deprecation.h \
  hash.h \
  httprpc.h \
  httpserver.h \
  init.h \
  key.h \
  key_io.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  lrucache.h \
  main.h \
  memusage.h \
  merkleblock.h \
  metrics.h \
  miner.h \
  pbaasrpc.h \
  mmr.h \
  mruset.h \
  net.h \
  netbase.h \
  noui.h \
  pbaas/crosschainrpc.h \
  pbaas/vdxf.h \
  pbaas/identity.h \
  pbaas/notarization.h \
  pbaas/pbaas.h \
  pbaas/reserves.h \
  policy/fees.h \
  pow.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  primitives/nonce.h \
  primitives/solutiondata.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/serverchecker.h \
  script/sign.h \
  script/standard.h \
  serialize.h \
  spentindex.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  timestampindex.h \
  tinyformat.h \
  torcontrol.h \
  transaction_builder.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  uint252.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltest.h \
  utiltime.h \
  validationinterface.h \
  version.h \
  wallet/asyncrpcoperation_common.h \
  wallet/asyncrpcoperation_mergetoaddress.h \
  wallet/asyncrpcoperation_saplingmigration.h \
  wallet/asyncrpcoperation_sendmany.h \
  wallet/asyncrpcoperation_shieldcoinbase.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/paymentdisclosure.h \
  wallet/paymentdisclosuredb.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  veruslaunch.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

  LIBTLS_H = \
      tls/utiltls.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	$(abs_top_srcdir)
libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: zcashd
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  sendalert.cpp \
  addrman.cpp \
  alert.cpp \
  alertkeys.h \
  asyncrpcoperation.cpp \
  asyncrpcqueue.cpp \
  bloom.cpp \
  cc/eval.cpp \
  cc/CCcustom.cpp \
  cc/CCutils.cpp \
  cc/StakeGuard.cpp \
  cc/StakeGuard.h \
  chain.cpp \
  cheatcatcher.h \
  cheatcatcher.cpp \
  checkpoints.cpp \
  crypto/haraka.h \
  crypto/haraka_portable.h \
  crypto/verus_clhash.h \
  crypto/verus_hash.h \
  crypto/verus_hash.cpp \
  deprecation.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  main.cpp \
  merkleblock.cpp \
  metrics.h \
  miner.cpp \
  net.cpp \
  noui.cpp \
  notarisationdb.cpp \
	params.cpp \
  pbaas/identity.cpp \
  pbaas/notarization.cpp \
  pbaas/pbaas.cpp \
  pbaas/reserves.cpp \
  policy/fees.cpp \
  pow.cpp \
  primitives/solutiondata.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/pbaasrpc.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/serverchecker.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H) \
  $(LIBTLS_H)

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
	zmq/zmqabstractnotifier.cpp \
	zmq/zmqnotificationinterface.cpp \
	zmq/zmqpublishnotifier.cpp
endif

if ENABLE_PROTON
libbitcoin_proton_a_CPPFLAGS = $(BITCOIN_INCLUDES)
libbitcoin_proton_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_proton_a_SOURCES = \
  amqp/amqpabstractnotifier.cpp \
  amqp/amqpnotificationinterface.cpp \
  amqp/amqppublishnotifier.cpp
endif

# wallet: zcashd, but only linked when wallet enabled
libbitcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_a_SOURCES = \
  transaction_builder.cpp \
  utiltest.cpp \
  utiltest.h \
  zcbenchmarks.cpp \
  zcbenchmarks.h \
  wallet/asyncrpcoperation_common.cpp \
  wallet/asyncrpcoperation_mergetoaddress.cpp \
  wallet/asyncrpcoperation_saplingmigration.cpp \
  wallet/asyncrpcoperation_sendmany.cpp \
  wallet/asyncrpcoperation_shieldcoinbase.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/paymentdisclosure.cpp \
  wallet/paymentdisclosuredb.cpp \
  wallet/rpcdisclosure.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

# crypto primitives library
crypto_libbitcoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libbitcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_a_SOURCES = \
  crypto/common.h \
  crypto/equihash.cpp \
  crypto/equihash.h \
  crypto/equihash.tcc \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/haraka.h \
  crypto/haraka_portable.h \
  crypto/verus_hash.h \
  crypto/verus_hash.cpp

if ENABLE_MINING
EQUIHASH_TROMP_SOURCES = \
	pow/tromp/equi_miner.h \
	pow/tromp/equi.h \
	pow/tromp/osx_barrier.h

crypto_libbitcoin_crypto_a_CPPFLAGS += \
	-DEQUIHASH_TROMP_ATOMIC
crypto_libbitcoin_crypto_a_SOURCES += \
	${EQUIHASH_TROMP_SOURCES}
endif

# Verus hash specific library - optimized
if ARCH_ARM
crypto_libverus_crypto_a_CPPFLAGS = -O3 -g -march=armv8.1-a+crypto -flax-vector-conversions -funroll-loops -fomit-frame-pointer -fPIC $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
crypto_libverus_crypto_a_CXXFLAGS = -O3 -Wno-error=attributes -Wint-conversion -g -march=armv8.1-a+crypto -flax-vector-conversions -funroll-loops -fomit-frame-pointer -fPIC $(AM_CXXFLAGS)
else
crypto_libverus_crypto_a_CPPFLAGS = -O3 -mpclmul -msse4 -msse4.1 -msse4.2 -mssse3 -maes -g -funroll-loops -fomit-frame-pointer -fPIC $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
crypto_libverus_crypto_a_CXXFLAGS = -O3 -Wint-conversion -mpclmul -msse4 -msse4.1 -msse4.2 -mssse3 -maes -g -funroll-loops -fomit-frame-pointer -fPIC $(AM_CXXFLAGS)
endif

crypto_libverus_crypto_a_SOURCES = \
  crypto/haraka.h \
  crypto/haraka.c \
  crypto/verus_clhash.h \
  crypto/verus_clhash.cpp

# Verus hash specific library - portable
if ARCH_ARM
crypto_libverus_portable_crypto_a_CPPFLAGS = -O3 -g -march=$(PLATFORM_VARIANT) -flax-vector-conversions -funroll-loops -fomit-frame-pointer -fPIC $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
crypto_libverus_portable_crypto_a_CXXFLAGS = -O3 -Wno-error=attributes -Wint-conversion -g -march=$(PLATFORM_VARIANT) -flax-vector-conversions -funroll-loops -fomit-frame-pointer -fPIC $(AM_CXXFLAGS)
else
crypto_libverus_portable_crypto_a_CPPFLAGS = -O3 -march=$(PLATFORM_VARIANT) -g -funroll-loops -fomit-frame-pointer -fPIC $(AM_CPPFLAGS) -w $(BITCOIN_INCLUDES)
crypto_libverus_portable_crypto_a_CXXFLAGS = -O3 -Wint-conversion -march=$(PLATFORM_VARIANT) -g -funroll-loops -fomit-frame-pointer -fPIC $(AM_CXXFLAGS)
endif

crypto_libverus_portable_crypto_a_SOURCES = \
  crypto/haraka_portable.h \
  crypto/haraka_portable.c \
  crypto/verus_clhash.h \
  crypto/verus_clhash_portable.cpp

# common: shared between zcashd and non-server tools
libbitcoin_common_a_CPPFLAGS = -fPIC $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_common_a_CXXFLAGS = -fPIC $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/params.cpp \
  consensus/upgrades.cpp \
  core_read.cpp \
  core_write.cpp \
  crypto/haraka.h \
  crypto/haraka_portable.h \
  crypto/verus_clhash.h \
  crypto/verus_hash.h \
  crypto/verus_hash.cpp \
  hash.cpp \
  key.cpp \
  key_io.cpp \
  keystore.cpp \
  netbase.cpp \
  metrics.cpp \
  mmr.cpp \
  pbaas/ethproof.cpp \
  pbaas/crosschainrpc.h \
  pbaas/crosschainrpc.cpp \
  pbaas/vdxf.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  primitives/nonce.cpp \
  primitives/solutiondata.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/cc.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_ext.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  veruslaunch.cpp \
  transaction_builder.cpp \
  utiltest.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_util_a_SOURCES = \
  support/pagelocker.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  crypto/chacha20.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: zcash-cli
libbitcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_cli_a_SOURCES = \
  arith_uint256.cpp \
  rpc/client.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
verusd_SOURCES = bitcoind.cpp
verusd_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
verusd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
verusd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
verusd_SOURCES += bitcoind-res.rc
endif

verusd_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_PROTON) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBVERUS_CRYPTO) \
  $(LIBVERUS_PORTABLE_CRYPTO) \
  $(LIBZCASH) \
  $(LIBTLS) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBCRYPTOCONDITIONS)

if ENABLE_WALLET
verusd_LDADD += $(LIBBITCOIN_WALLET)
endif

verusd_LDADD += \
  $(BOOST_LIBS) \
  $(BDB_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_PTHREADS_LIBS) \
  $(EVENT_LIBS) \
  $(ZMQ_LIBS) \
  $(PROTON_LIBS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBVERUS_CRYPTO) \
  $(LIBVERUS_PORTABLE_CRYPTO) \
  $(LIBZCASH_LIBS)

if ENABLE_PROTON
verusd_LDADD += $(LIBBITCOIN_PROTON) $(PROTON_LIBS)
endif

# bitcoin-cli binary #
verus_SOURCES = bitcoin-cli.cpp
verus_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
verus_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
verus_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

# wallet-utility binary #
if ENABLE_WALLET
wallet_utility_SOURCES = wallet-utility.cpp
wallet_utility_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
wallet_utility_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
wallet_utility_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)
endif

if TARGET_WINDOWS
verus_SOURCES += bitcoin-cli-res.rc
endif

verus_LDADD = \
	$(LIBBITCOIN_CLI) \
	$(LIBUNIVALUE) \
	$(LIBBITCOIN_UTIL) \
	$(BOOST_LIBS) \
	$(SSL_LIBS) \
	$(CRYPTO_LIBS) \
	$(EVENT_LIBS) \
	$(LIBZCASH) \
	$(LIBTLS) \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBVERUS_CRYPTO) \
	$(LIBVERUS_PORTABLE_CRYPTO) \
	$(LIBZCASH_LIBS)

if ENABLE_WALLET
wallet_utility_LDADD = \
	$(LIBBITCOIN_WALLET) \
	$(LIBBITCOIN_COMMON) \
	$(LIBCURL) \
    $(LIBUNIVALUE) \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBVERUS_CRYPTO) \
	$(LIBVERUS_PORTABLE_CRYPTO) \
	$(LIBSECP256K1) \
	$(LIBBITCOIN_UTIL) \
	$(BOOST_LIBS) \
	$(BDB_LIBS) \
	$(CRYPTO_LIBS) \
	$(EVENT_LIBS) \
	$(LIBZCASH) \
	$(LIBZCASH_LIBS)\
	$(LIBCRYPTOCONDITIONS)
endif

# zcash-tx binary #
verus_tx_SOURCES = komodo-tx.cpp
verus_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
verus_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
verus_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
verus_tx_SOURCES += bitcoin-tx-res.rc
endif

verus_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(BOOST_LIBS) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(EVENT_LIBS) \
  $(LIBSECP256K1) \
  $(LIBZCASH) \
  $(LIBTLS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBVERUS_CRYPTO) \
  $(LIBVERUS_PORTABLE_CRYPTO) \
  $(LIBZCASH_LIBS) \
  $(LIBCRYPTOCONDITIONS)

verus_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(LIBCURL)
#

# zcash protocol primitives #
libzcash_a_SOURCES = \
	zcash/IncrementalMerkleTree.cpp \
	zcash/NoteEncryption.cpp \
	zcash/Address.cpp \
	zcash/address/sapling.cpp \
    zcash/address/sprout.cpp \
    zcash/address/zip32.cpp \
	zcash/JoinSplit.cpp \
	zcash/Proof.cpp \
	zcash/Note.cpp \
	zcash/prf.cpp \
	zcash/util.cpp \
    zcash/address/zip32.cpp

libzcash_a_CPPFLAGS = $(AM_CPPFLAGS) $(PIC_FLAGS) $(BITCOIN_INCLUDES)
libzcash_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libzcash_a_LDFLAGS = $(AM_LDFLAGS)

# zcashconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/zcashconsensus.h
libzcashconsensus_la_SOURCES = \
  crypto/equihash.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  pbaas/crosschainrpc.h \
  pbaas/crosschainrpc.cpp \
  primitives/transaction.cpp \
  primitives/nonce.cpp \
  pubkey.cpp \
  script/zcashconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
libzcashconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libzcashconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libzcashconsensus_la_LIBADD = $(LIBSECP256K1)
libzcashconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -I$(srcdir)/cryptoconditions/include -DBUILD_BITCOIN_INTERNAL -w
libzcashconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

libtls_a_SOURCES = \
    tls/utiltls.cpp\
    tls/tlsmanager.cpp

libtls_a_CPPFLAGS = -DMULTICORE -fPIC -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS $(HARDENED_CPPFLAGS) -pipe -O2 -g  -Wstack-protector -fstack-protector-all -fPIE -fvisibility=hidden -DSTATIC $(BITCOIN_INCLUDES)

libtls_a_CXXFLAGS = $(HARDENED_CXXFLAGS) -fwrapv -fno-strict-aliasing

libtls_a_LDFLAGS = $(HARDENED_LDFLAGS)

libtls_a_CPPFLAGS += -DMONTGOMERY_OUTPUT

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno */*.gcno wallet/*/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_TESTS
include Makefile.ktest.include
#include Makefile.test.include
#include Makefile.gtest.include
endif
