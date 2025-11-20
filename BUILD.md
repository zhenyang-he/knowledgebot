# Building and Pushing Docker Image

The GitLab CI pipeline builds the Go binary automatically. To build and push the Docker image to Harbor, you have two options:

## Option 1: Build Locally (Recommended)

1. Make sure you have the binary built (from CI artifacts or build locally):
   ```bash
   go build -o knowledgebot main.go
   ```

2. Build the Docker image:
   ```bash
   docker build -t harbor.test.shopeemobile.com/knowledgebot/knowledgebot:latest .
   ```

3. Login to Harbor:
   ```bash
   docker login harbor.test.shopeemobile.com
   ```

4. Push the image:
   ```bash
   docker push harbor.test.shopeemobile.com/knowledgebot/knowledgebot:latest
   ```

## Option 2: Use the Original Dockerfile

The original `Dockerfile` includes a build stage, so you can build directly:

```bash
docker build -t harbor.test.shopeemobile.com/knowledgebot/knowledgebot:latest -f Dockerfile .
docker login harbor.test.shopeemobile.com
docker push harbor.test.shopeemobile.com/knowledgebot/knowledgebot:latest
```

## Note

The GitLab CI runner environment doesn't support Docker-in-Docker, Kaniko, Buildah, or Podman due to permission/configuration limitations. The CI pipeline will build the binary, and you can build/push the Docker image manually or use a different CI/CD service that supports container builds.

