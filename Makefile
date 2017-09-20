flake:
	@if command -v flake8 > /dev/null; then \
		echo "Running flake8"; \
		flake8 flake8 --ignore N802,N806,W503 `find . -name \*.py | grep -v setup.py | grep -v /doc/`; \
	else \
		echo "flake8 not found, please install it!"; \
		exit 1; \
	fi;
	@echo "flake8 passed"

test:
	py.test --pyargs cloudknot --cov-report term-missing --cov=cloudknot
