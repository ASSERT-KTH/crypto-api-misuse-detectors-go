ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG GIT_TAG

# Clone repository based on whether GIT_TAG or GIT_COMMIT is provided
RUN if [ -n "${GIT_TAG}" ]; then \
        git clone --depth 1 --branch ${GIT_TAG} ${REPO_URL} .; \
    else \
        echo "Error: GIT_TAG must be provided" && \
        exit 1; \
    fi


#RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# scripts and executables
COPY ./rename_json.sh /analysis/rename_json.sh
# TODO compile to binary and run binary
COPY ./extract /analysis/extract

# Set working directory and define command
WORKDIR /analysis/gopher
CMD /bin/sh -c "./gopher ../repo && ../rename_json.sh ../repo && cd /analysis/extract && go run main.go -results ../repo/scan_results/results.json -repo ../repo"