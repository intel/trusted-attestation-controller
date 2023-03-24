ARG GO_VERSION="1.20"

FROM golang:${GO_VERSION} as builder

WORKDIR /
COPY LICENSE LICENSE
COPY go.mod go.mod
COPY go.sum go.sum
COPY controllers controllers
COPY pkg pkg
COPY plugins plugins
COPY main.go main.go

RUN GOOS=linux GOARCH=amd64 go build -a -buildmode=pie -o manager /main.go
RUN GOOS=linux GOARCH=amd64 go build -a -buildmode=pie -o kmra-plugin /plugins/kmra/main.go
RUN GOOS=linux GOARCH=amd64 go build -a -buildmode=pie -o null-plugin /plugins/null/main.go
RUN GOOS=linux GOARCH=amd64 go build -a -buildmode=pie -o isecl-plugin /plugins/isecl/main.go
RUN mkdir -p /usr/local/share/package-licenses \
  && cp /usr/local/go/LICENSE /usr/local/share/package-licenses/go.LICENSE \
  && cp LICENSE /usr/local/share/package-licenses/trusted-attestation-controller.LICENSE

FROM gcr.io/distroless/base

WORKDIR /
COPY --from=builder /manager .
COPY --from=builder /kmra-plugin .
COPY --from=builder /null-plugin .
COPY --from=builder /isecl-plugin .
COPY --from=builder /usr/local/share/package-licenses /usr/local/share/package-licenses
USER 5000:5000
ENTRYPOINT ["/manager"]
