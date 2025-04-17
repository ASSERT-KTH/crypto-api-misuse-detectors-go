ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG RELEASE_TAG
ARG GIT_COMMIT 
# TODO not sending commit at this point

# Clone repository based on whether GIT_TAG or GIT_COMMIT is provided
RUN if [ -n "${GIT_TAG}" ]; then \
        git clone --depth 1 --branch ${GIT_TAG} ${REPO_URL} .; \
    elif [ -n "${GIT_COMMIT}" ]; then \
        git clone ${REPO_URL} . && \
        git checkout ${GIT_COMMIT}; \
    else \
        echo "Error: Either GIT_TAG or GIT_COMMIT must be provided" && \
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