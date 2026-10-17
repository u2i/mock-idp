# Build a fully static binary, then ship it on distroless/static — no
# shell, no package manager, no libc. The dev IdP has zero third-party
# dependencies, so the final image is just the ~7MB binary plus CA certs
# and a nonroot user from the distroless base.
# Cross-compile on the build host's arch for each target (no QEMU needed).
FROM --platform=$BUILDPLATFORM golang:1.23.4-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
# go.mod first for layer caching; there are no deps to download.
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /idp .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /idp /idp
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/idp"]
