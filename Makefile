# SPDX-License-Identifier: LGPL-2.1-only

ifeq ($(TEST),)
TEST=*
endif

ifeq ($(FAILFAST),)
FAILFAST=0
endif

TEST_ARGS=-p=$(TEST) -f=$(FAILFAST)

ifneq ($(PROFILE),)
TEST_ARGS += --profile $(PROFILE)
endif

ifneq ($(TESTER_INTERFACE),)
TEST_ARGS += --tester-interface $(TESTER_INTERFACE)
endif

ifneq ($(TESTED_INTERFACE),)
TEST_ARGS += --tested-interface $(TESTED_INTERFACE)
endif

ifneq ($(TAGS),)
TEST_ARGS += --tags $(TAGS)
endif

ifneq ($(BASELINE),)
TEST_ARGS += --baseline $(BASELINE)
endif

ifneq ($(CPUS),)
TEST_ARGS += --cpus $(CPUS)
else
ifneq ($(CPU_COUNT),)
TEST_ARGS += -c $(CPU_COUNT)
else
TEST_ARGS += -c 2
endif
endif

ifneq ($(CONNECT),)
TEST_ARGS += --connect $(CONNECT)
endif

ifneq ($(VERBOSE),)
TEST_ARGS += --verbose $(VERBOSE)
endif

.PHONY: fix-codestyle
fix-codestyle:
	find  -name '*.c' -o -name '*.h' | xargs clang-format --style=file -i

.PHONY: build-debug
build-debug:
	ninja -C build-debug
.PHONY: test-debug
test-debug: build-debug
	./scripts/run-unit-tests.sh build-debug '$(TEST)' $(FAILFAST)
	./test/run.py $(TEST_ARGS) --builddir=./build-debug

.PHONY: build-release
build-release:
	ninja -C build-release
.PHONY: test-release
test-release: build-release
	./scripts/run-unit-tests.sh build-release '$(TEST)' $(FAILFAST)
	./test/run.py $(TEST_ARGS) --builddir=./build-release

.PHONY: build-debugoptimized
build-debugoptimized:
	ninja -C build-debugoptimized
.PHONY: test-debugoptimized
test-debugoptimized: build-debugoptimized
	./scripts/run-unit-tests.sh build-debugoptimized '$(TEST)' $(FAILFAST)
	./test/run.py $(TEST_ARGS) --builddir=./build-debugoptimized

.PHONY: clean
clean:
	rm -rf build-debug build-release build-debugoptimized
	find ./py -name '*_pb2.py' | xargs rm -f
	find -name '__pycache__' | xargs rm -rf
	find -name config.py | xargs rm -f
