FROM golang:latest AS build_base

WORKDIR /work
COPY . .

RUN CGO_ENABLED=0 go build -o kube-sentry main.go

FROM cgr.dev/chainguard/static:latest
COPY --from=build_base /work/kube-sentry /kube-sentry

ENTRYPOINT ["/kube-sentry"]