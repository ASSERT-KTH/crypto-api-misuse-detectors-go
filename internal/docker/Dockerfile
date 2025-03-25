ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG VUL_TAG

RUN git clone --depth 1 --branch ${VUL_TAG} ${REPO_URL} .
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY ./rename_json.sh /analysis/rename_json.sh
COPY ./extract /analysis/extract

WORKDIR /analysis/gopher
CMD /bin/sh -c "./gopher ../repo && ../rename_json.sh ../repo && cd /analysis/extract && go run main.go -results ../repo/scan_results/results.json -repo ../repo"
