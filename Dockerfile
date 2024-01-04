# First stage: build the executable.
FROM golang:alpine
# Set the Current Working Directory inside the container
WORKDIR /app
# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all the dependencies
RUN go mod download
# Copy the source from the current directory to the Working Directory inside the container
COPY *.go .
# Build the Go app
RUN go build -o main .

# Second stage: build the final container.
FROM alpine:latest
# Set the Current Working Directory inside the container
WORKDIR /app
# Copy the Pre-built binary file from the previous stage
COPY --from=0 /app/main .
# Expose port 8080 to the outside world
EXPOSE 8080
# Command to run the executable
CMD ["./main"]