ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG GIT_TAG
ARG GIT_COMMIT


# Clone repository based on whether GIT_TAG or GIT_COMMIT is provided
RUN if [ -n "${GIT_TAG}" ]; then \
        git clone --depth 1 --branch "${GIT_TAG}" "${REPO_URL}" .; \
    elif [ -n "${GIT_COMMIT}" ]; then \
        git clone "${REPO_URL}" . && \
        git checkout "${GIT_COMMIT}"; \
    else \
        echo "Error: GIT_TAG or GIT_COMMIT must be provided" && \
        exit 1; \
    fi

WORKDIR /analysis

# No default CMD - will be overridden by tool-specific Dockerfiles