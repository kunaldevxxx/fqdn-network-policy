FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/manager ./cmd

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/manager /manager
ENTRYPOINT ["/manager"]
