.PHONY: default
default: help

.PHONY: help
help:
	@echo "make help              Show this help message"
	@echo "make dev               Run the app in the development server"
	@echo "make lint              Run the code linter(s) and print any warnings"
	@echo "make format            Correctly format the code"
	@echo "make checkformatting   Crash if the code isn't correctly formatted"
	@echo "make test              Run the unit tests"
	@echo "make sure              Make sure that the formatter, linter, tests, etc all pass"
	@echo "make docker            Make the app's Docker image"
	@echo "make clean             Delete development artefacts (cached files, "
	@echo "                       dependencies, etc)"
	@echo "make requirements      Compile all requirements files"

.PHONY: dev
dev: python
	@tox -qe dev

.PHONY: dev-ssl
dev-ssl: python
	@tox -qe dev-ssl

.PHONY: test
test: python
	@tox -q

.PHONY: docker
docker:
	@docker build -t hypothesis/via:$(DOCKER_TAG) .

.PHONY: lint
lint: python
	@tox -qe lint

.PHONY: format
format: python
	@tox -qe py36-format

.PHONY: checkformatting
checkformatting: python
	@tox -qe py36-checkformatting

.PHONY: sure
sure: checkformatting lint test

.PHONY: clean
clean:
	@find . -type f -name "*.py[co]" -delete
	@find . -type d -name "__pycache__" -delete

.PHONY: requirements
requirements:
	@sh requirements/compile.sh

.PHONY: python
python:
	@./bin/install-python

DOCKER_TAG = latest
