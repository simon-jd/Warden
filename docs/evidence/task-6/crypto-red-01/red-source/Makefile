.PHONY: azure-down azure-preflight test-azure-budget
# rg-mlinfra-westus is always protected. No target/scope override is accepted.
azure-down:
	python3 -B scripts/azure_guard.py down $(if $(filter 1,$(DRY_RUN)),--dry-run,)
azure-preflight:
	python3 -B scripts/azure_guard.py preflight
test-azure-budget:
	python3 -B -m unittest scripts.test_azure_guard -v
