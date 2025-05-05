ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG GIT_TAG

# Clone repository based on whether GIT_TAG or GIT_COMMIT is provided
# TODO! change to commit.
RUN if [ -n "${GIT_TAG}" ]; then \
        git clone --depth 1 --branch ${GIT_TAG} ${REPO_URL} .; \
    else \
        echo "Error: GIT_TAG must be provided" && \
        exit 1; \
    fi

# Common utilities and scripts
COPY ./rename_json.sh /analysis/rename_json.sh
COPY ./extract /analysis/extract

WORKDIR /analysis

# No default CMD - will be overridden by tool-specific Dockerfiles