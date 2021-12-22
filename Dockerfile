FROM golang:1.14-alpine AS builder

RUN mkdir /app
COPY . /app
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux go build -o keycloak-go-client ./main.go

FROM alpine:latest AS production
RUN apk update
RUN apk add --no-cache bash
COPY --from=builder /app/keycloak-go-client /
CMD ["./keycloak-go-client"]