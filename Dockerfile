ARG GO_VERSION="1.18"

FROM golang:${GO_VERSION} as builder

WORKDIR /
COPY go.mod go.mod
COPY go.sum go.sum
COPY controllers controllers
COPY pkg pkg
COPY plugins plugins
COPY main.go main.go

RUN GOOS=linux GOARCH=amd64 go build -a -o manager /main.go
RUN GOOS=linux GOARCH=amd64 go build -a -o kmra-plugin /plugins/kmra/main.go

FROM gcr.io/distroless/base-debian11

WORKDIR /
COPY --from=builder /manager .
COPY --from=builder /kmra-plugin .
USER 5000:5000
ENTRYPOINT ["/manager"]
