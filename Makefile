.PHONY: help run-rss run-opencti run-slack run-splunk build serve clean \
        tf-init tf-plan tf-apply tf-destroy

SOURCE ?= rss

help:
	@echo "Threat Intel Pipeline"
	@echo ""
	@echo "Laptop usage (requires .env):"
	@echo "  make run-rss       Fetch from RSS feeds and build the dashboard"
	@echo "  make run-opencti   Fetch from OpenCTI and build the dashboard"
	@echo "  make run-slack     Fetch from Slack and build the dashboard"
	@echo "  make run-splunk    Fetch from Splunk and build the dashboard"
	@echo "  make build         Re-run build.py without re-fetching"
	@echo "  make serve         Serve the dashboard at http://localhost:8080"
	@echo "  make clean         Remove generated pipeline files"
	@echo ""
	@echo "Docker usage:"
	@echo "  make docker-rss       docker compose --profile rss up --build"
	@echo "  make docker-opencti   docker compose --profile opencti up --build"
	@echo "  make docker-serve     docker compose --profile serve up"
	@echo ""
	@echo "Terraform (AWS + Aviatrix):"
	@echo "  make tf-init          terraform init"
	@echo "  make tf-plan          terraform plan"
	@echo "  make tf-apply         terraform apply"
	@echo "  make tf-destroy       terraform destroy"

# ── Laptop targets ─────────────────────────────────────────────────────────────
# Load .env if present, then run. Works with or without direnv.

run-rss:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 run.py --source rss --build

run-opencti:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 run.py --source opencti --build

run-slack:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 run.py --source slack --build

run-splunk:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 run.py --source splunk --build

build:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 generator/build.py

serve:
	@echo "Serving at http://localhost:8080"
	@python3 -m http.server 8080 --directory data

clean:
	rm -f /tmp/tw-30d*.json /tmp/tw-30d*.pkl /tmp/threat-watch*.html /tmp/threat-watch*.json
	rm -f data/tw-30d*.json data/tw-30d*.pkl data/threat-watch*.html data/threat-watch*.json

# ── Docker targets ─────────────────────────────────────────────────────────────

docker-rss:
	docker compose --profile rss up --build

docker-opencti:
	docker compose --profile opencti up --build

docker-slack:
	docker compose --profile slack up --build

docker-splunk:
	docker compose --profile splunk up --build

docker-serve:
	docker compose --profile serve up

# ── Terraform targets ──────────────────────────────────────────────────────────

tf-init:
	cd terraform && terraform init

tf-plan:
	cd terraform && terraform plan

tf-apply:
	cd terraform && terraform apply

tf-destroy:
	cd terraform && terraform destroy
