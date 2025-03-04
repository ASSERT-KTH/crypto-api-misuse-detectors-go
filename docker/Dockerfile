ARG GO_VERSION
FROM golang:${GO_VERSION}

WORKDIR /analysis/repo

ARG REPO_URL
ARG VUL_TAG

RUN git clone --depth 1 --branch ${VUL_TAG} ${REPO_URL} .
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY ./rename_json.sh /analysis/rename_json.sh
CMD /bin/sh -c "/analysis/gopher/gopher /analysis/repo && /analysis/rename_json.sh /analysis/repo"
