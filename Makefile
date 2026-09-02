.DEFAULT_GOAL := fixture-verify

.PHONY: prefetch fixture-verify zero-bill

prefetch fixture-verify zero-bill:
	@python3 ci/run_make_target.py $@
