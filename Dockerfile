FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/controlplane ./cmd/controlplane && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/proxy ./cmd/proxy

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/controlplane /app/controlplane
COPY --from=build /out/proxy /app/proxy
EXPOSE 8080 8081
CMD ["/app/controlplane"]
