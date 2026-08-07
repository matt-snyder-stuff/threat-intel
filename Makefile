.PHONY: help run-rss run-opencti run-slack run-splunk run-stix build serve clean \
        docker-rss docker-opencti docker-slack docker-splunk docker-stix docker-serve \
        test test-docker \
        opencti-up opencti-seed opencti-down \
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
	@echo "  make run-stix      Fetch from STIX/TAXII and build the dashboard"
	@echo "  make build         Re-run build.py without re-fetching"
	@echo "  make serve         Serve the dashboard at http://localhost:8080"
	@echo "  make clean         Remove generated pipeline files"
	@echo ""
	@echo "Docker usage:"
	@echo "  make docker-rss       docker compose --profile rss up --build"
	@echo "  make docker-opencti   docker compose --profile opencti up --build"
	@echo "  make docker-stix      docker compose --profile stix up --build"
	@echo "  make docker-serve     docker compose --profile serve up"
	@echo ""
	@echo "Validation:"
	@echo "  make test           Run RSS pipeline + validate output (local)"
	@echo "  make test-docker    Build image, run RSS+OpenCTI(mock) pipelines in Docker, validate"
	@echo ""
	@echo "OpenCTI live instance (http://localhost:8080):"
	@echo "  make opencti-up     Start full OpenCTI stack and wait until ready"
	@echo "  make opencti-seed   Load 10 demo threat reports into running OpenCTI"
	@echo "  make opencti-down   Stop and remove all OpenCTI containers + volumes"
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

run-stix:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 run.py --source stix --build

build:
	@[ -f .env ] && set -a && . ./.env && set +a; python3 generator/build.py

serve:
	@echo "Serving at http://localhost:8080"
	@python3 -m http.server 8080 --directory data

clean:
	rm -f /tmp/tw-30d*.json /tmp/tw-30d*.pkl /tmp/threat-watch*.html /tmp/threat-watch*.json
	rm -f data/tw-30d*.json data/tw-30d*.pkl data/threat-watch*.html data/threat-watch*.json

# ── Test targets ───────────────────────────────────────────────────────────────

test:
	@[ -f .env ] && set -a && . ./.env && set +a; \
	python3 run.py --source rss --build && \
	PKL_IN=/tmp/tw-30d-processed.pkl JSON_IN=/tmp/threat-watch-data.json python3 tests/validate.py

test-docker:
	@mkdir -p /tmp/ti-test-rss /tmp/ti-test-opencti /tmp/ti-test-splunk
	docker build -t threat-intel-pipeline:dev .
	@echo ""
	@echo "--- RSS ---"
	docker run --rm -v /tmp/ti-test-rss:/data \
	  -e PKL_OUT=/data/tw-30d-processed.pkl \
	  -e PUB_SIDECAR=/data/tw-30d-published.json \
	  -e HTML_OUT=/data/threat-watch.html \
	  -e JSON_OUT=/data/threat-watch-data.json \
	  -e CUTOFF_DAYS=30 \
	  threat-intel-pipeline:dev --source rss --build
	docker run --rm -v /tmp/ti-test-rss:/data -v ./tests:/app/tests \
	  -e PKL_IN=/data/tw-30d-processed.pkl \
	  -e JSON_IN=/data/threat-watch-data.json \
	  --entrypoint python3 threat-intel-pipeline:dev tests/validate.py
	@echo ""
	@echo "--- OpenCTI (mock) ---"
	python3 tests/mock_opencti.py --port 18080 & echo $$! > /tmp/ti-mock-opencti.pid; sleep 1
	docker run --rm -v /tmp/ti-test-opencti:/data \
	  --add-host host.docker.internal:host-gateway \
	  -e PKL_OUT=/data/tw-30d-processed.pkl \
	  -e RAW_OUT=/data/tw-30d.json \
	  -e PUB_SIDECAR=/data/tw-30d-published.json \
	  -e HTML_OUT=/data/threat-watch.html \
	  -e JSON_OUT=/data/threat-watch-data.json \
	  -e OPENCTI_URL=http://host.docker.internal:18080/graphql \
	  -e OPENCTI_TOKEN=mock-token \
	  -e CUTOFF_DAYS=30 \
	  threat-intel-pipeline:dev --source opencti --build; \
	  kill $$(cat /tmp/ti-mock-opencti.pid) 2>/dev/null; rm -f /tmp/ti-mock-opencti.pid
	docker run --rm -v /tmp/ti-test-opencti:/data -v ./tests:/app/tests \
	  -e PKL_IN=/data/tw-30d-processed.pkl \
	  -e JSON_IN=/data/threat-watch-data.json \
	  --entrypoint python3 threat-intel-pipeline:dev tests/validate.py

# ── Docker targets ─────────────────────────────────────────────────────────────

docker-rss:
	docker compose --profile rss up --build

docker-opencti:
	docker compose --profile opencti up --build

docker-slack:
	docker compose --profile slack up --build

docker-splunk:
	docker compose --profile splunk up --build

docker-stix:
	docker compose --profile stix up --build

docker-serve:
	docker compose --profile serve up

# ── OpenCTI live instance ─────────────────────────────────────────────────────
# Starts a full OpenCTI stack (ES + Redis + RabbitMQ + MinIO + platform)
# and seeds it with 10 demo threat reports.
# Login: admin@opencti.io / ChangeMe1234!  UI: http://localhost:8080

opencti-up:
	docker compose -f tests/docker-compose.opencti.yml up -d
	@echo "Waiting for OpenCTI to be ready..."
	@python3 -c "
import urllib.request, json, time, sys
token = '8ac2c1f9-0b3d-4f24-a621-4c9b1f2e5a37'
deadline = time.time() + 300
while time.time() < deadline:
    try:
        req = urllib.request.Request('http://localhost:8080/graphql',
            data=b'{\"query\":\"{ about { version } }\"}',
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'})
        d = json.loads(urllib.request.urlopen(req, timeout=5).read())
        if d.get('data', {}).get('about', {}).get('version'):
            print('  Ready:', d['data']['about']['version']); sys.exit(0)
    except Exception: pass
    sys.stdout.write('.'); sys.stdout.flush(); time.sleep(5)
print('Timed out'); sys.exit(1)
"

opencti-seed:
	python3 tests/seed_opencti.py

opencti-down:
	docker compose -f tests/docker-compose.opencti.yml down -v

# ── Terraform targets ──────────────────────────────────────────────────────────

tf-init:
	cd terraform && terraform init

tf-plan:
	cd terraform && terraform plan

tf-apply:
	cd terraform && terraform apply

tf-destroy:
	cd terraform && terraform destroy
