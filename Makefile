.PHONY: install lint typecheck test test-cov clean build publish

install:
	pip install -e ".[dev,web]"

lint:
	ruff check src/

lint-fix:
	ruff check --fix src/

typecheck:
	mypy src/

test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ --cov=threatlens --cov-report=term

test-cov-html:
	python -m pytest tests/ --cov=threatlens --cov-report=html

check: lint typecheck test

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

build: clean
	hatch build

publish: build
	hatch publish

serve:
	threatlens serve --host 127.0.0.1 --port 8080

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down
