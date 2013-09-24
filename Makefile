ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
UGLIFYJS=node_modules/.bin/uglifyjs
WD=`pwd`

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
	lib/util.js 
	date > $@

build: $(BUILD_STAMP) 

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

test: test-server

clean:
	rm -f lib/*.js $(BUILD_STAMP) $(TEST_STAMP)

setup:
	npm install -d

.PHONY: clean setup test 
