.PHONY: help lint test test-cli demo run-demo pdf airlock all

PDF_SRC    := $(if $(wildcard AUTHORIZATION_MATRIX_POLICY_AS_CODE.md),AUTHORIZATION_MATRIX_POLICY_AS_CODE.md,README.md)
PDF_OUT    := AUTHORIZATION_MATRIX_POLICY_AS_CODE.pdf
PDF_CSS    := docs/pdf-style.css
PDF_TITLE  := Enterprise IAM Authorization Matrices with Policy as Code
PDF_AUTHOR := Arjan Filius

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

lint: ## Verify Rego formatting and strict static checks
	opa fmt --fail policies/ > /dev/null
	opa check --strict policies/

test: ## Run all OPA unit tests
	opa test -v policies/

test-cli: ## Run automated Python CLI pipeline tests
	python3 -m unittest discover -s scripts -v

demo: ## Evaluate all 6 example JSON fixtures with raw opa eval
	@for f in diff_valid_nonprod diff_valid_tier0_high_cia diff_removal diff_heuristics_warn diff_violations; do \
		echo "=== $$f ==="; \
		opa eval --format=pretty -d policies -i "examples/data/$${f}.json" "data.iam.matrix.approval.decision"; \
	done
	@echo "=== tscm_sweep_enriched ==="
	@opa eval --format=pretty -d policies -i examples/data/tscm_sweep_enriched.json "data.iam.matrix.tscm.report"

run-demo: ## Run the 4-layer executable CLI demo across key scenarios
	@python3 scripts/iam_matrix_check.py --matrix examples/data/diff_valid_tier0_high_cia.json
	@python3 scripts/iam_matrix_check.py --matrix examples/data/diff_heuristics_warn.json
	@python3 scripts/iam_matrix_check.py --matrix examples/data/diff_violations.json || true
	@python3 scripts/iam_matrix_check.py --matrix examples/data/tscm_sweep_enriched.json \
		--ad examples/mock_sources/ad_accounts.json \
		--cmdb examples/mock_sources/cmdb_machines.json

pdf: ## Build executive A4 PDF from Markdown via pandoc + weasyprint
	pandoc $(PDF_SRC) \
		--from=gfm \
		--standalone \
		--embed-resources \
		--resource-path=. \
		--css=$(PDF_CSS) \
		--metadata title="$(PDF_TITLE)" \
		--metadata author="$(PDF_AUTHOR)" \
		--pdf-engine=weasyprint \
		-o $(PDF_OUT)
	@ls -lh $(PDF_OUT)

airlock: ## Sync allowlisted clean files to sibling public Git Airlock repo
	@./scripts/airlock_sync.sh

all: lint test test-cli run-demo pdf ## Run lint, OPA & CLI tests, live demo, and rebuild PDF
