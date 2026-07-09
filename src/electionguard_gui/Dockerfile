FROM ubuntu:24.04
COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

##################################################################################
# Install python
##################################################################################

RUN uv python install 3.14

##################################################################################
# Install EG prerequisites
##################################################################################

RUN apt-get update && apt-get install -y libgmp-dev libmpfr-dev libmpc-dev

##################################################################################
# Virtualenv and dependencies setup
##################################################################################

RUN mkdir /app
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv venv

##################################################################################
# Get Source
##################################################################################

# cleanup first, the next layer will get invalidated easiliy
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY ./src ./src
RUN rm src/electionguard_gui/__init__.py

##################################################################################
# Run EGUI
##################################################################################

# the final uv sync runs fast, it activates the virtualenv and initializes the modules
RUN uv sync --all-groups --locked

ENTRYPOINT ["uv", "run", "--locked", "egui"]
# alternately, for testing:
# ENTRYPOINT ["tail", "-f", "/dev/null"]
