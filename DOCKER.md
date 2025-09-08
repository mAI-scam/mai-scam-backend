# Docker Deployment Guide

This document provides instructions for building and running the MAI Scam Detection API using Docker.

## Prerequisites

- Docker installed and running
- `.env` file configured with required environment variables

## Building the Docker Image

Build the Docker image using the following command:

```bash
docker build -t mai-scam-api .
```

This will:
- Use AWS Lambda Python 3.10 runtime as base image
- Install all dependencies from `requirements.txt`
- Copy application files to the container
- Set up the Lambda handler

## Running the Docker Container

### Method 1: Local Development Server

Run the container as a local FastAPI server:

```bash
docker run --rm -p 8000:8000 \
    --entrypoint python \
    --env-file .env \
    mai-scam-api app.py
```

This will:
- Start the FastAPI server on port 8000
- Load environment variables from `.env` file
- Enable hot reload and debugging features

### Method 2: Lambda Handler Mode

Run the container using the default Lambda handler:

```bash
docker run --rm -p 9000:8080 \
    --env-file .env \
    mai-scam-api
```

This mode simulates the AWS Lambda runtime environment.

## Testing the API

Once the container is running, test the endpoints:

### Health Check
```bash
curl http://localhost:8000/
```

### Service Health
```bash
curl http://localhost:8000/health
```

### API Documentation
Visit: `http://localhost:8000/docs` in your browser

## Docker Commands Reference

### View running containers
```bash
docker ps
```

### Stop a running container
```bash
docker stop <container_id>
```

### Remove the image
```bash
docker rmi mai-scam-api
```

### View container logs
```bash
docker logs <container_id>
```

### Clean up unused images and containers
```bash
docker system prune
```

## Troubleshooting

### Port Already in Use
If port 8000 is already in use:
```bash
# Find the process using the port
lsof -ti:8000

# Kill the process
kill $(lsof -ti:8000)

# Or use a different port
docker run --rm -p 8001:8000 --entrypoint python --env-file .env mai-scam-api app.py
```

### Environment Variables
Ensure your `.env` file contains all required variables:
- AWS credentials (if using AWS services)
- Database connection strings
- API keys and secrets

### Build Issues
If the build fails:
1. Check your `requirements.txt` for conflicts
2. Ensure Docker daemon is running
3. Try rebuilding without cache: `docker build --no-cache -t mai-scam-api .`

## File Structure

The Docker setup includes these key files:
- `Dockerfile` - Container build instructions
- `.dockerignore` - Files excluded from build context
- `requirements.txt` - Python dependencies
- `.env` - Environment variables (not committed to git)

## Next Steps

After successful Docker testing, the image is ready for AWS Lambda deployment using CDK.