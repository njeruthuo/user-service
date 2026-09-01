FROM golang:latest as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${GOARCH} go run build -o /out/usr-svc

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/usr-svc ./usr-svc

EXPOSE 8000

USER nonroot

ENTRYPOINT [ "./usr-svc" ]
