FROM ubuntu:noble

# avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    gcc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*


ENV GO_VERSION=1.23.3

RUN wget -P /tmp "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    tar -C /usr/local -xzf /tmp/go${GO_VERSION}.linux-amd64.tar.gz && \
    rm /tmp/go${GO_VERSION}.linux-amd64.tar.gz

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

RUN useradd -m -s /bin/bash dev
WORKDIR /home/dev/go/src
#USER dev
COPY ./gopher ./gopher
COPY ./test/projects ./test/projects
COPY ./test/run_gopher.sh ./run_gopher.sh

RUN chmod +x ./run_gopher.sh

CMD ["tail", "-f", "/dev/null"]