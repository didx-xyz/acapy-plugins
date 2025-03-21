FROM python:3.12-slim AS base
WORKDIR /usr/src/app

# Install and configure poetry
USER root

ENV POETRY_VERSION=1.7.1
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir redis_events && touch redis_events/__init__.py
COPY pyproject.toml poetry.lock README.md ./
ARG install_flags='--with integration --extras aca-py'
RUN poetry install ${install_flags}
USER $user

FROM python:3.12-bullseye
WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"

# TODO: install from 1.1.0 tag when available
RUN pip install git+https://github.com/jamshale/aries-acapy-plugins@feat/1055-prepare-for-move-to-owf#subdirectory=basicmessage_storage

COPY redis_events/ redis_events/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "integration.yml"]