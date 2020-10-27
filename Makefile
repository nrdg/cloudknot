.PHONY: clean clean-test clean-pyc clean-build flake lint

flake:
	flake8
	black --check .
	pydocstyle

lint: flake

test:
    # Unit testing using pytest
	pytest --pyargs cloudknot --cov-report term-missing --cov-config .coveragerc --cov=cloudknot

devtest:
    # Unit testing with the -x option, aborts testing after first failure
    # Useful for development when tests are long
	pytest -x --pyargs cloudknot --cov-report term-missing --cov-config .coveragerc --cov=cloudknot

clean: clean-build clean-pyc ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

release: dist ## Package and upload a release
	twine upload dist/*

dist: clean ## Build source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel --universal
	ls -l dist

