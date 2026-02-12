FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /siem .

FROM golang:1.22-alpine AS test
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["go", "test", "./..."]

FROM alpine:latest
RUN adduser -D samma
WORKDIR /app
COPY --from=builder /siem /app/siem
RUN chown -R samma:samma /app
USER samma
EXPOSE 8080
CMD ["/app/siem"]
