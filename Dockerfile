FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate


FROM node:22-alpine AS console_build
WORKDIR /wconsole
COPY web/console/package.json web/console/package-lock.json ./
RUN npm ci
COPY web/console/ ./
RUN npm run build:static
WORKDIR /wops
COPY web/ops/package.json web/ops/package-lock.json ./
RUN npm ci
COPY web/ops/ ./
RUN npm run build:static

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=build /out/controlplane /app/controlplane
COPY --from=build /out/proxy /app/proxy
COPY --from=build /out/migrate /app/migrate
COPY web /app/web
COPY --from=console_build /wconsole/out /app/web/console
EXPOSE 8080 8081
CMD ["/app/controlplane"]
