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

$(BUILD_STAMP): \
	lib/const.js \
	lib/main.js \
	lib/primegen.js \
	lib/primes.js \
	lib/random.js \
	lib/rsa.js \
	lib/util.js \
	lib/bn.js \
	lib/cfb.js \
	lib/s2k.js \
	lib/hash.js \
	lib/encode/pad.js \
	lib/encode/armor.js \
	lib/keygen.js \
	lib/kbpacket/base.js \
	lib/kbpacket/keymaterial.js \
	lib/kbpacket/encode.js \
	lib/packet/base.js \
	lib/packet/userid.js \
	lib/packet/keymaterial.js \
	lib/packet/signature.js \
	lib/packet/parser.js \
	lib/packet/buffer.js \
	lib/sign.js \
	lib/basex.js \
	lib/cast5.js \
	lib/asymmetric.js \
	lib/symmetric.js
	date > $@

build: $(BUILD_STAMP) 

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

test-browser: $(TEST_STAMP) $(BUILD_STAMP)
	@echo "Please visit in your favorite browser --> file://$(WD)/test/browser/index.html"

test/browser/test.js: test/browser/main.iced $(BUILD_STAMP)
	$(BROWSERIFY) -t icsify $< > $@

$(TEST_STAMP): test/browser/test.js
	date > $@

test: test-server test-browser

clean:
	rm -f lib/encode/*.js lib/packet/*.js lib/kbpacket/*.js lib/*.js $(BUILD_STAMP) $(TEST_STAMP) test/browser/test.js

setup:
	npm install -d

.PHONY: clean setup test  test-browser
