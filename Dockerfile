# syntax=docker/dockerfile:1

#####################
## STAGE 1 - Build ##
#####################

# Base image for the application
FROM golang:1.24-alpine AS build-stage

# Working directory
WORKDIR /app

# Modules and dependencies
COPY go.mod ./
RUN go mod download

# Copy source code
COPY *.go ./

# Compile
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /isis_account

####################
## STAGE 2 - Test ##
####################

# Run tests
FROM build-stage AS test-stage
RUN go test -v ./...

######################
## STAGE 3 - Deploy ##
######################

# Deploy to lean image
FROM scratch AS deploy-stage
WORKDIR /

# Copy binary from build stage
COPY --from=build-stage /isis_account /isis_account

# Expose port
ARG PORT
EXPOSE $PORT

# Deployt
ENTRYPOINT ["/isis_account"]