# The index digest is Docker Official golang:1.26.10-bookworm, linux/amd64.
FROM --platform=linux/amd64 golang:1.26.10-bookworm@sha256:88750ccdd0f2a77fcc00a14b1a48d6409bd8ddb5d7c2dd6ec0b4a2e916daf9d9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY controlplane/ ./controlplane/
COPY runtimes/runtime.go ./runtimes/
COPY runtimes/gate/ ./runtimes/gate/
COPY runtimes/runc/ ./runtimes/runc/
COPY policies/seccomp/ ./policies/seccomp/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/warden-api ./controlplane/cmd/warden-api

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build --chown=65532:65532 /out/warden-api /warden-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/warden-api"]
