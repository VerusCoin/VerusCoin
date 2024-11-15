# Copyright (c) 2016-2019 The Zcash developers
# Copyright (c) 2013-2019 The Bitcoin Core developers
# Copyright (c) 2013-2019 Bitcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

ACLOCAL_AMFLAGS = -I build-aux/m4
# print the triplets
$(info *********** BUILD_TRIPLET is set to: $(build_triplet) ***********)
$(info *********** HOST_TRIPLET is set to: $(host_triplet) ***********)

SUBDIRS = src
if ENABLE_MAN
SUBDIRS += doc/man
endif
.PHONY: deploy FORCE

GZIP_ENV="-9n"

if BUILD_BITCOIN_LIBS
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzcashconsensus.pc
endif


BITCOIND_BIN=$(top_builddir)/src/verusd$(EXEEXT)
BITCOIN_CLI_BIN=$(top_builddir)/src/verus$(EXEEXT)
#WALLET_UTILITY_BIN=$(top_builddir)/src/wallet-utility$(EXEEXT)
BITCOIN_WIN_INSTALLER=$(PACKAGE)-$(PACKAGE_VERSION)-win$(WINDOWS_BITS)-setup$(EXEEXT)


DIST_DOCS = $(wildcard doc/*.md) $(wildcard doc/release-notes/*.md)

BIN_CHECKS=$(top_srcdir)/contrib/devtools/symbol-check.py \
	$(top_srcdir)/contrib/devtools/security-check.py



WINDOWS_PACKAGING = $(top_srcdir)/share/pixmaps/bitcoin.ico \
	$(top_srcdir)/share/pixmaps/nsis-header.bmp \
	$(top_srcdir)/share/pixmaps/nsis-wizard.bmp


if TARGET_DARWIN
COVERAGE_INFO = baseline_filtered_combined.info baseline.info block_test.info \
	leveldb_baseline.info test_bitcoin_filtered.info total_coverage.info \
	baseline_filtered.info block_test_filtered.info \
	leveldb_baseline_filtered.info test_bitcoin_coverage.info test_bitcoin.info
#  zcash-gtest.info zcash-gtest_filtered.info zcash-gtest_coverage.info
else
COVERAGE_INFO = baseline_filtered_combined.info baseline.info block_test.info \
  leveldb_baseline.info test_bitcoin_filtered.info total_coverage.info \
  baseline_filtered.info \
  leveldb_baseline_filtered.info test_bitcoin_coverage.info test_bitcoin.info \
  #zcash-gtest.info zcash-gtest_filtered.info zcash-gtest_coverage.info
endif

LCOV_EXCLUDE_PATTERNS = "/usr/include/*" \
	"$(abs_builddir)/depends/$(host_triplet)/include/*.h" \
	"$(abs_builddir)/depends/$(host_triplet)/include/boost/*" \
	"$(abs_builddir)/depends/$(host_triplet)/include/gmock/*" \
	"$(abs_builddir)/depends/$(host_triplet)/include/gtest/*" \
	"$(abs_builddir)/src/gtest/*" \
	"$(abs_builddir)/src/test/*" \
	"$(abs_builddir)/src/wallet/gtest/*" \
	"$(abs_builddir)/src/wallet/test/*"

dist-hook:
	-$(MAKE) -C $(top_distdir)/src/leveldb clean
	-$(MAKE) -C $(top_distdir)/src/secp256k1 distclean
	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -

distcheck-hook:
	$(MKDIR_P) $(top_distdir)/_build/src/leveldb
	cp -rf $(top_srcdir)/src/leveldb/* $(top_distdir)/_build/src/leveldb/
	-$(MAKE) -C $(top_distdir)/_build/src/leveldb clean

distcleancheck:
	@:

$(if $(findstring src/,$(MAKECMDGOALS)),$(MAKECMDGOALS), none): FORCE
	$(MAKE) -C src $(patsubst src/%,%,$@)


if TARGET_WINDOWS
deploy: $(BITCOIN_WIN_INSTALLER)
endif

$(BITCOIND_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_CLI_BIN): FORCE
	$(MAKE) -C src $(@F)

#$(WALLET_UTILITY_BIN): FORCE
#	$(MAKE) -C src $(@F)

if USE_LCOV

baseline.info:
	$(LCOV) -c -i -d $(abs_builddir)/src -o $@

if BUILD_DARWIN
baseline_filtered.info: baseline.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
else
baseline_filtered.info: baseline.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
endif

leveldb_baseline.info: baseline_filtered.info
	$(LCOV) -c -i -d $(abs_builddir)/src/leveldb -b $(abs_builddir)/src/leveldb -o $@

if BUILD_DARWIN
leveldb_baseline_filtered.info: leveldb_baseline.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
else
leveldb_baseline_filtered.info: leveldb_baseline.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
endif

baseline_filtered_combined.info: leveldb_baseline_filtered.info baseline_filtered.info
	$(LCOV) -a leveldb_baseline_filtered.info -a baseline_filtered.info -o $@

test_bitcoin.info: baseline_filtered_combined.info
	$(MAKE) -C src/ bitcoin_test_check
	$(LCOV) -c -d $(abs_builddir)/src -t test_bitcoin -o $@
	$(LCOV) -z -d $(abs_builddir)/src
	$(LCOV) -z -d $(abs_builddir)/src/leveldb

if BUILD_DARWIN
test_bitcoin_filtered.info: test_bitcoin.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
else
test_bitcoin_filtered.info: test_bitcoin.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
endif


block_test.info: test_bitcoin_filtered.info
	$(MKDIR_P) qa/tmp
	-@TIMEOUT=15 qa/pull-tester/run-bitcoind-for-test.sh $(JAVA) -jar $(JAVA_COMPARISON_TOOL) qa/tmp/compTool 0
	$(LCOV) -c -d $(abs_builddir)/src --t BitcoinJBlockTest -o $@
	$(LCOV) -z -d $(abs_builddir)/src
	$(LCOV) -z -d $(abs_builddir)/src/leveldb

if BUILD_DARWIN
block_test_filtered.info: block_test.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
else
block_test_filtered.info: block_test.info
	$(LCOV) -r $< $(LCOV_EXCLUDE_PATTERNS) -o $@
endif


test_bitcoin_coverage.info: baseline_filtered_combined.info test_bitcoin_filtered.info
	$(LCOV) -a baseline_filtered.info -a leveldb_baseline_filtered.info -a test_bitcoin_filtered.info -o $@

if ! BUILD_DARWIN
zcash-gtest_coverage.info: baseline_filtered_combined.info zcash-gtest_filtered.info
	$(LCOV) -a baseline_filtered.info -a leveldb_baseline_filtered.info -a zcash-gtest_filtered.info -o $@
endif

if BUILD_DARWIN
total_coverage.info:  baseline_filtered_combined.info test_bitcoin_filtered.info zcash-gtest_filtered.info block_test_filtered.info
	$(LCOV) -a baseline_filtered.info -a leveldb_baseline_filtered.info -a test_bitcoin_filtered.info -a zcash-gtest_filtered.info -a block_test_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt
else
total_coverage.info:  baseline_filtered_combined.info test_bitcoin_filtered.info zcash-gtest_filtered.info block_test_filtered.info
	$(LCOV) -a baseline_filtered.info -a leveldb_baseline_filtered.info -a test_bitcoin_filtered.info -a zcash-gtest_filtered.info -a block_test_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt
endif


test_bitcoin.coverage/.dirstamp:  test_bitcoin_coverage.info
	$(GENHTML) -s $< -o $(@D)
	@touch $@

if TARGET_DARWIN
zcash-gtest.coverage/.dirstamp:  zcash-gtest_coverage.info
	$(GENHTML) -s $< -o $(@D)
	@touch $@
cov-zcash: zcash-gtest.coverage/.dirstamp
endif

total.coverage/.dirstamp: total_coverage.info
	$(GENHTML) -s $< -o $(@D)
	@touch $@

if BUILD_DARWIN
cov: test_bitcoin.coverage/.dirstamp cov-zcash total.coverage/.dirstamp
else
cov: test_bitcoin.coverage/.dirstamp cov-zcash total.coverage/.dirstamp
endif

endif

dist_bin_SCRIPTS = zcutil/fetch-params.sh
dist_noinst_SCRIPTS = autogen.sh zcutil/build-debian-package.sh zcutil/build.sh

EXTRA_DIST = $(top_srcdir)/share/genbuild.sh qa/pull-tester/rpc-tests.sh qa/pull-tester/run-bitcoin-cli qa/rpc-tests qa/zcash $(DIST_DOCS) $(BIN_CHECKS)

install-exec-hook:
	mv $(DESTDIR)$(bindir)/fetch-params.sh $(DESTDIR)$(bindir)/zcash-fetch-params

.INTERMEDIATE: $(COVERAGE_INFO)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

clean-local:
	rm -rf test_bitcoin.coverage/ zcash-gtest.coverage/ total.coverage/
