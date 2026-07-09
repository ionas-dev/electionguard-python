.PHONY: all environment openssl-fix install build auto-lint lint validate test test-example unit-tests property-tests integration-tests coverage coverage-html coverage-xml coverage-erase bench fetch-sample-data generate-sample-data docs-serve docs-build docs-deploy-ci dependency-graph-ci publish-ci publish-test-ci release-zip-ci release-notes egui start-db stop-db build-egui start-egui stop-egui eg-e2e-simple-election eg-setup-simple-election

UV := $(shell command -v uv 2>/dev/null || true)
ifeq ($(UV),)
$(warning uv not found. Install uv (curl -LsSf https://astral.sh/uv/install.sh | sh) to use Makefile targets)
endif

CODE_COVERAGE ?= 90
OS ?= $(shell uname -s)
ifeq ($(OS), Linux)
PKG_MGR ?= $(shell command -v apt-get >/dev/null 2>&1 && echo apt-get || { command -v pacman >/dev/null 2>&1 && echo pacman; } || echo undefined)
endif
SAMPLE_BALLOT_COUNT ?= 5
SAMPLE_BALLOT_SPOIL_RATE ?= 50

all: environment install build validate auto-lint coverage

environment:
	@echo 🔧 ENVIRONMENT SETUP
	@echo 📦 Install gmp
	@echo Operating System identified as $(OS)
	@if [ "$(OS)" = "Linux" ]; then \
		echo 🐧 LINUX INSTALL; \
		if [ "$(PKG_MGR)" = "apt-get" ]; then \
			sudo apt-get update; \
			sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev; \
		elif [ "$(PKG_MGR)" = "pacman" ]; then \
			sudo pacman -S --noconfirm gmp; \
		else \
			echo "We could not install GMP automatically for your Linux distribution. Please, install GMP manually."; \
		fi; \
	elif [ "$(OS)" = "Darwin" ]; then \
		echo 🍎 MACOS INSTALL; \
		brew install gmp || true; \
		brew install mpfr || true; \
		brew install libmpc || true; \
	fi
	uv venv --allow-existing
	make fetch-sample-data

install:
	@echo 🔧 INSTALL
	uv sync --all-groups --locked

build:
	@echo 🔨 BUILD
	uv build

openssl-fix:
	export LDFLAGS=-L/usr/local/opt/openssl/lib
	export CPPFLAGS=-I/usr/local/opt/openssl/include 

lint:
	@echo 💚 LINT
	@echo 1.Pylint
	uv run --locked pylint --extension-pkg-allow-list=dependency_injector ./src ./tests
	@echo 2.Black Formatting
	uv run --locked black --check .
	@echo 3.Mypy Static Typing
	uv run --locked mypy src/electionguard src/electionguard_tools src/electionguard_cli src/electionguard_gui stubs
	@echo 4.Package Metadata
	uv build
	uv run --locked twine check dist/*
	@echo 5.Documentation
	uv run --locked mkdocs build --strict

auto-lint:
	@echo 💚 AUTO LINT
	@echo Auto-generating __init__
	uv run --locked mkinit src/electionguard --write --black
	uv run --locked mkinit src/electionguard_tools --write --recursive --black
	uv run --locked mkinit src/electionguard_verify --write --black
	uv run --locked mkinit src/electionguard_cli --write --recursive --black
	uv run --locked mkinit src/electionguard_gui --write --recursive --black
	@echo Reformatting using Black
	uv run --locked black .
	make lint

validate: 
	@echo ✅ VALIDATE
	@uv run python -c 'import electionguard; print(electionguard.__package__ + " successfully imported")'

# Test
unit-tests:
	@echo ✅ UNIT TESTS
	uv run --locked pytest tests/unit

property-tests:
	@echo ✅ PROPERTY TESTS
	uv run --locked pytest tests/property

integration-tests:
	@echo ✅ INTEGRATION TESTS
	uv run --locked pytest tests/integration

test: 
	@echo ✅ ALL TESTS
	make unit-tests
	make property-tests
	make integration-tests

test-example:
	@echo ✅ TEST Example
	uv run --locked pytest -s tests/integration/test_end_to_end_election.py

# Coverage
coverage:
	@echo ✅ COVERAGE
	uv run --locked coverage run -m pytest
	uv run --locked coverage report --fail-under=$(CODE_COVERAGE)

coverage-html:
	uv run --locked coverage html -d coverage

coverage-xml:
	uv run --locked coverage xml

coverage-erase:
	@uv run --locked coverage erase

# Benchmark
bench:
	@echo 📊 BENCHMARKS
	uv run --locked python -s tests/bench/bench_chaum_pedersen.py

# Documentation

docs-serve:
	uv run --locked mkdocs serve

docs-build:
	uv run --locked mkdocs build

docs-deploy-ci:
	@echo 🚀 DEPLOY to Github Pages
	uv run --locked mkdocs gh-deploy --force

dependency-graph-ci:
	sudo apt install graphviz
	uv run --locked pydeps --noshow --max-bacon 2 -o dependency-graph.svg src/electionguard

# Sample Data
fetch-sample-data:
	@echo ⬇️ FETCH Sample Data
	wget -O sample-data.zip https://github.com/Election-Tech-Initiative/electionguard/releases/download/v1.0/sample-data.zip
	unzip -o sample-data.zip

generate-sample-data:
	@echo 🔁 GENERATE Sample Data
	uv run --locked python src/electionguard_tools/scripts/sample_generator.py -m "hamilton-general" -n $(SAMPLE_BALLOT_COUNT) -s $(SAMPLE_BALLOT_SPOIL_RATE)

# Publish

publish-ci:
	@echo 🚀 PUBLISH
	uv publish --username __token__ --password $(PYPI_TOKEN)

publish-test-ci:
	@echo 🚀 PUBLISH TEST
	uv publish --publish-url https://test.pypi.org/legacy/ --username __token__ --password $(TEST_PYPI_TOKEN)

# Release
release-zip-ci:
	@echo 📁 ZIP RELEASE ARTIFACTS
	mv dist electionguard
	mv dependency-graph.svg electionguard
	zip -r electionguard.zip electionguard

release-notes:
	@echo 📝 GENERATE RELEASE NOTES
	export MILESTONE_NUM=$(cat ${GITHUB_EVENT_PATH} | jq '.milestone.number')
	export MILESTONE_URL=$(cat ${GITHUB_EVENT_PATH} | jq '.milestone.url')
	export MILESTONE_TITLE=$(cat ${GITHUB_EVENT_PATH} | jq '.milestone.title')
	export MILESTONE_DESCRIPTION=$(cat ${GITHUB_EVENT_PATH} | jq '.milestone.description')
	touch release_notes.md
	echo "# ${MILESTONE_TITLE}" >> release_notes.md
	echo "${MILESTONE_DESCRIPTION}" >> release_notes.md
	echo -en "\n" >> release_notes.md
	echo "## Issues" >> release_notes.md
	curl "${GITHUB_API_URL}/${GITHUB_REPOSITORY}/issues?milestone=${MILESTONE_NUM}&state=all" | jq '.[].title' | while read i; do echo "[$i](${MILESTONE_URL})" >> release_notes.md; done

egui:
ifeq "${EG_DB_PASSWORD}" ""
	@echo "Set the EG_DB_PASSWORD environment variable"
	exit 1
endif
	uv run --locked egui

start-db:
	sudo apt install -y docker-compose
ifeq "${EG_DB_PASSWORD}" ""
	@echo "Set the EG_DB_PASSWORD environment variable"
	exit 1
endif
	docker compose --env-file ./.env -f src/electionguard_db/docker-compose.db.yml up -d

stop-db:
	docker compose --env-file ./.env -f src/electionguard_db/docker-compose.db.yml down

build-egui:
	docker build -t egui -f ./src/electionguard_gui/Dockerfile .

start-egui: build-egui
	sudo apt install -y docker-compose
ifeq "${EG_DB_PASSWORD}" ""
	@echo "Set the EG_DB_PASSWORD environment variable"
	exit 1
endif
	docker compose --env-file ./.env -f src/electionguard_gui/docker-compose.yml up -d

stop-egui:
	docker compose --env-file ./.env -f src/electionguard_gui/docker-compose.yml down

eg-e2e-simple-election:
	uv run --locked eg e2e --guardian-count=2 --quorum=2 --manifest=data/election_manifest_simple.json --ballots=data/plaintext_ballots_simple.json --spoil-id=25a7111b-4334-425a-87c1-f7a49f42b3a2 --output-record="./election_record.zip"

eg-setup-simple-election:
	uv run --locked eg setup --guardian-count=2 --quorum=2 --manifest=data/election_manifest_simple.json  --package-dir=../data/out/public_encryption_package --keys-dir=../data/out/test_data_private_guardian_data
