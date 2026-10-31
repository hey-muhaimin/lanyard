FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --chmod=0755 controlplane /app/controlplane
COPY --chmod=0755 proxy /app/proxy
COPY --chmod=0755 migrate /app/migrate
COPY web /app/web
EXPOSE 8080 8081
CMD ["/app/controlplane"]
