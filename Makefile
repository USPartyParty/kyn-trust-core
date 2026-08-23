.PHONY: check format lint locks package test typecheck

check: locks lint typecheck test package

locks:
	uv lock --check

lint:
	uv run ruff format --check src tests
	uv run ruff check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

test:
	uv run pytest

typecheck:
	uv run mypy

package:
	@build_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$build_dir"' EXIT; \
	uv build --out-dir "$$build_dir" --no-create-gitignore
