FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=build /out/controlplane /app/controlplane
COPY --from=build /out/proxy /app/proxy
COPY web /app/web
EXPOSE 8080 8081
CMD ["/app/controlplane"]
