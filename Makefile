.PHONY: install test lint check clean demo refund-demo verify web-install web-dev web-build up down migrate loadtest docs preflight release-dry-run doctor helm-lint

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest

lint:
	python -m ruff check src sdk-python tests api

check: lint test

demo:
	python -m agentblackbox demo

refund-demo:
	python examples/refund_agent_demo.py --output examples/output

verify:
	python -m agentblackbox verify $(BUNDLE) $(if $(PUBLIC_KEY),--public-key $(PUBLIC_KEY),)

web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

up:
	docker compose up -d --build

down:
	docker compose down

migrate:
	python -c "from api.app.main import app; app.state.repository.initialize(); print('SQLite schema initialized')"

loadtest:
	python scripts/loadtest.py

docs:
	python -m http.server 8765 --directory docs

release-dry-run:
	python scripts/release_dry_run.py

preflight:
	python scripts/preflight.py

doctor:
	python scripts/doctor.py

helm-lint:
	python scripts/preflight.py

clean:
	python -c "import shutil; shutil.rmtree('build', ignore_errors=True); shutil.rmtree('dist', ignore_errors=True); shutil.rmtree('.pytest_cache', ignore_errors=True); shutil.rmtree('.ruff_cache', ignore_errors=True)"
