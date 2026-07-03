# SecureVault — Developer Convenience Targets
# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

.PHONY: help install test security terraform-plan terraform-apply simulate-finding deploy clean

PYTHON := python
VENV   := .venv
SRC    := src
TF     := terraform

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install Python dependencies into the active virtual environment
	$(PYTHON) -m pip install -r $(SRC)/requirements.txt
	$(PYTHON) -m pip install pytest bandit pip-audit checkov truffleHog functions-framework

test: ## Run pytest suite
	pytest -q

security: ## Run all security scanners (bandit, pip-audit, Checkov, truffleHog)
	bandit -r $(SRC)/ -ll
	pip-audit -r $(SRC)/requirements.txt --desc
	checkov -d $(TF)/ --framework terraform --quiet
	truffleHog filesystem . --only-verified

terraform-plan: ## Validate and plan Terraform changes
	cd $(TF) && terraform fmt -recursive
	cd $(TF) && terraform validate
	cd $(TF) && terraform plan -input=false -out=plan.tfplan

terraform-apply: ## Apply a previously saved Terraform plan
	cd $(TF) && terraform apply -input=false plan.tfplan

simulate-finding: ## Publish a sample SCC finding to the scc-findings topic
	$(PYTHON) scripts/simulate_finding.py --project $(or $(PROJECT_ID),$(shell gcloud config get-value project 2>/dev/null)) --finding-class PUBLIC_BUCKET_ACL

deploy: terraform-apply ## Deploy infrastructure and Cloud Function (requires GCP auth)
	@echo "Infrastructure applied. The Cloud Function is deployed by Terraform."

clean: ## Remove Python cache, Terraform plan artifacts, and source zip
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -f $(TF)/plan.tfplan $(SRC).zip
