REPORTER = dot
test:
	@NODE_ENV=test ./node_modules/.bin/mocha -R $(REPORTER) test

.PHONY: test