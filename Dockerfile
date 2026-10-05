# routini-runner container image.
#
#   docker build -t routini/runner:dev .
#   docker run --init -e ROUTINI_RUNNER_URL=http://server:3001 -e ROUTINI_RUNNER_TOKEN=rre_... routini/runner:dev
#
# `up` enrolls on first start (when the config file is missing), then runs.

FROM golang:1.22 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Leave VERSION empty to keep the version compiled into internal/version.
ARG VERSION=""
RUN LDFLAGS="-s -w"; \
    if [ -n "$VERSION" ]; then LDFLAGS="$LDFLAGS -X github.com/nvasion/routini-runner/internal/version.Version=${VERSION#v}"; fi; \
    go build -trimpath -ldflags "$LDFLAGS" -o /out/routini-runner ./cmd/routini-runner

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 routini-runner \
 && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/routini-runner --shell /bin/bash routini-runner
COPY --from=build /out/routini-runner /usr/local/bin/routini-runner
ENV ROUTINI_RUNNER_CONFIG=/home/routini-runner/.config/routini-runner/config.json
USER routini-runner
WORKDIR /home/routini-runner
ENTRYPOINT ["routini-runner"]
CMD ["up"]
