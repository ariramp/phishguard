FROM golang:1.25 AS build
WORKDIR /app

RUN apt-get update && apt-get install -y git ca-certificates && rm -rf /var/lib/apt/lists/*

ENV GOPROXY=direct
ENV GOSUMDB=sum.golang.org
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o phishguard-agent ./cmd/agent

FROM debian:stable-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/phishguard-agent .
EXPOSE 8080
CMD ["./phishguard-agent"]