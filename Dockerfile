FROM golang:latest AS build

# copy project files into container work dir
WORKDIR /work
COPY . .

# update packages and install upx packer
RUN apt-get update -y && \
    apt-get install -y upx

# build Go binary
# remove debugging information and compress binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o kube-sentry main.go
#RUN upx --brute kube-sentry

# copy binary into distroless image
FROM cgr.dev/chainguard/static:latest
COPY --from=build /work/kube-sentry /kube-sentry

ENTRYPOINT ["/kube-sentry"]