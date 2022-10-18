FROM golang:latest AS build

# copy project files into container work dir
WORKDIR /work
COPY . .

# install dependencies
RUN apt-get update -y && \
    apt-get install -y upx && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# build Go binary
# remove debugging information and compress binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o kube-sentry main.go
#RUN upx --brute kube-sentry

# copy binary into smaller image
FROM alpine:latest
COPY --from=build /work/kube-sentry /kube-sentry
COPY --from=build /usr/local/bin/trivy /usr/local/bin/trivy

ENTRYPOINT ["/kube-sentry"]