
ICED=node_modules/.bin/iced

test: 
	$(ICED) test/run.iced


.PHONY: test