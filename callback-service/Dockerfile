FROM golang:1.22-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o callback-service main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/callback-service /app/callback-service
EXPOSE 7000
CMD ["/app/callback-service"]

