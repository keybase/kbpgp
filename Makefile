ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
UGLIFYJS=node_modules/.bin/uglifyjs
WD=`pwd`
BROWSERIFY=node_modules/.bin/browserify

default: build
all: build

lib/%.js: src/%.iced
	$(ICED) -I browserify -c -o `dirname $@` $<

BROWSER=browser/kbpgp.js

$(BUILD_STAMP): \
	lib/asymmetric.js \
	lib/basekeypair.js \
	lib/basex.js \
	lib/bn.js \
	lib/const.js \
	lib/dsa.js \
	lib/ecc/base.js \
	lib/ecc/curves.js \
	lib/ecc/ecdh.js \
	lib/ecc/ecdsa.js \
	lib/ecc/eddsa.js \
	lib/ecc/main.js \
	lib/elgamal.js \
	lib/elgamalse.js \
	lib/errors.js \
	lib/hash.js \
	lib/header.js \
	lib/keybase/encode.js \
	lib/keybase/hilev.js \
	lib/keybase/packet/alloc.js \
	lib/keybase/packet/base.js \
	lib/keybase/packet/encryption.js \
	lib/keybase/packet/p3skb.js \
	lib/keybase/packet/signature.js \
	lib/keybase/util.js \
	lib/keyfetch.js \
	lib/keyring.js \
	lib/keywrapper.js \
	lib/kmi.js \
	lib/main.js \
	lib/nacl/base.js \
	lib/nacl/main.js \
	lib/nacl/eddsa.js \
	lib/nacl/dh.js \
	lib/openpgp/armor.js \
	lib/openpgp/baseburner.js \
	lib/openpgp/buffer.js \
	lib/openpgp/burner.js \
	lib/openpgp/cast5.js \
	lib/openpgp/cfb.js \
	lib/openpgp/clearsign.js \
	lib/openpgp/detachsign.js \
	lib/openpgp/hilev.js \
	lib/openpgp/keymanager.js \
	lib/openpgp/ocfb.js \
	lib/openpgp/packet/all.js \
	lib/openpgp/packet/base.js \
	lib/openpgp/packet/compressed.js \
	lib/openpgp/packet/generic.js \
	lib/openpgp/packet/literal.js \
	lib/openpgp/packet/keymaterial.js \
	lib/openpgp/packet/one_pass_sig.js \
	lib/openpgp/packet/packetsigs.js \
	lib/openpgp/packet/sess.js \
	lib/openpgp/packet/signature.js \
	lib/openpgp/packet/userid.js \
	lib/openpgp/packet/user_attribute.js \
	lib/openpgp/parser.js \
	lib/openpgp/processor.js \
	lib/openpgp/sigeng.js \
	lib/openpgp/s2k.js \
	lib/openpgp/util.js \
	lib/openpgp/verifier.js \
	lib/pad.js \
	lib/primegen.js \
	lib/primes.js \
	lib/rand.js \
	lib/rfc3394.js \
	lib/rsa.js \
	lib/symmetric.js \
	lib/ukm.js \
	lib/util.js
	date > $@

build: $(BUILD_STAMP)

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

test-browser: $(TEST_STAMP) $(BUILD_STAMP)
	@echo "Please visit in your favorite browser --> file://$(WD)/test/browser/index.html"

test/browser/test.js: test/browser/main.iced $(BUILD_STAMP)
	$(BROWSERIFY) -t icsify $< > $@

test/benchmark/keybase.js: bench/main.js $(BUILD_STAMP)
	$(BROWSERIFY) -s keybase $< > $@

$(TEST_STAMP): test/browser/test.js
	date > $@

test: test-server test-browser

$(BROWSER): lib/main.js $(BUILD_STAMP)
	$(BROWSERIFY) -s kbpgp $< > $@

release: $(BROWSER)
	V=`jsonpipe < package.json | grep version | awk '{ print $$2 }' | sed -e s/\"//g` ; \
	cp $< rel/kbpgp-$$V.js ; \
	$(UGLIFYJS) -c < rel/kbpgp-$$V.js > rel/kbpgp-$$V-min.js ; \
	rm -rf rel/kbpgp-$$V-signed-release.zip ; \
	rm -rf rel/kbpgp ; \
	mkdir rel/kbpgp ; \
	cp rel/kbpgp-$$V.js     rel/kbpgp/ ; \
	cp rel/kbpgp-$$V-min.js rel/kbpgp/ ; \
	pushd rel/ ; \
	keybase dir sign -p none kbpgp/ ; \
	zip kbpgp-$$V-signed-release.zip kbpgp/*.js kbpgp/*.md ; \
	popd ; \
	rm -rf rel/kbpgp
	keybase dir sign

clean:
	rm -rf lib/* $(BUILD_STAMP) $(TEST_STAMP) test/browser/test.js

setup:
	npm install -d

.PHONY: clean setup test  test-browser
