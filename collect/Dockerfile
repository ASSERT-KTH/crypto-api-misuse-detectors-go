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

# adds GitHub to known hosts 
RUN mkdir -p /home/dev/.ssh && \
    ssh-keyscan github.com >> /home/dev/.ssh/known_hosts

#RUN git clone https://github.com/yxzhang2024/gopher.git

CMD ["tail", "-f", "/dev/null"]