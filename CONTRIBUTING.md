# Contributing to ThreatLens

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/threatlens
cd threatlens
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,web]"
```

## Code Quality

```bash
ruff check src/
python -m pytest tests/ -v --cov=threatlens
```

## Guidelines

- Type hints required for all code
- Docstrings on all public functions and classes
- Follow existing patterns (see `src/threatlens/`)
- Tests required for new features (minimum 70 total)
- Coverage should stay above 80%

## Pull Request Process

1. Create a feature branch from `main`
2. Run lint and tests locally
3. Keep changes focused — one feature per PR
4. Update tests and documentation as needed
5. Request review from maintainers

## Release Process

1. Update version in `src/threatlens/_version.py` and `pyproject.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `hatch run check`
4. Build: `hatch build`
5. Publish: `hatch publish`
