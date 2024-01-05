# First stage: build the executable.
FROM golang:alpine as builder
# Set the Current Working Directory inside the container
WORKDIR /app
# Enable caching for go build
RUN go env -w GOCACHE=/go-cache
# Eable caching for go modules
RUN go env -w GOMODCACHE=/gomod-cache
# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all the dependencies
RUN --mount=type=cache,target=/gomod-cache go mod download
# Copy the source from the current directory to the Working Directory inside the container
COPY *.go .
# Build the Go app
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache go build -o main .

# Second stage: build the final container.
FROM alpine:latest
# Set the Current Working Directory inside the container
WORKDIR /app
# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .
# Expose port 8080 to the outside world
EXPOSE 8080
# Command to run the executable
CMD ["./main"]