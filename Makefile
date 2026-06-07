.PHONY: install test lint typecheck format check clean

install:
	uv sync --frozen

test:
	uv run pytest --cov=rapid7_mcp --cov-report=term-missing tests/

lint:
	uv run ruff check .

typecheck:
	uv run mypy rapid7_mcp/

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

check: lint typecheck test

clean:
	rm -rf .ruff_cache/ .mypy_cache/ .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true