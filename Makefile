ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
UGLIFYJS=node_modules/.bin/uglifyjs
WD=`pwd`
BROWSERIFY=node_modules/.bin/browserify

default: build
all: build

lib/%.js: src/%.iced
	$(ICED) -I browserify -c -o lib $<

$(BUILD_STAMP): \
	lib/const.js \
	lib/main.js \
	lib/pgp.js \
	lib/primegen.js \
	lib/primes.js \
	lib/random.js \
	lib/rsa.js \
	lib/util.js \
	lib/bn.js \
	lib/cfb.js \
	lib/s2k.js
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
	rm -f lib/*.js $(BUILD_STAMP) $(TEST_STAMP) test/browser/test.js

setup:
	npm install -d

.PHONY: clean setup test  test-browser
