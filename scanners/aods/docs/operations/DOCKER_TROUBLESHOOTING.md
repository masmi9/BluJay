# Docker Troubleshooting Guide

This document covers common Docker issues encountered in AODS development, particularly with Docker Desktop on WSL2.

## Table of Contents

1. [Docker Desktop Credential Store Issues](#docker-desktop-credential-store-issues)
2. [WSL2 Socket Communication Errors](#wsl2-socket-communication-errors)
3. [Build Context Too Large](#build-context-too-large)
4. [BuildKit Syntax Directive Failures](#buildkit-syntax-directive-failures)
5. [gRPC Connection Errors](#grpc-connection-errors)

---

## Docker Desktop Credential Store Issues

### Symptom

```
error getting credentials - err: exit status 1, out: ""
```

This error occurs when Docker tries to use the credential helper configured by Docker Desktop but fails to communicate with it.

### Cause

Docker Desktop on Windows configures `~/.docker/config.json` with:
```json
{
  "credsStore": "desktop.exe"
}
```

When using Docker from WSL2, this credential helper may not be accessible or may fail silently.

### Solution

1. **Reset Docker config** (removes credential store reference):
   ```bash
   echo '{}' > ~/.docker/config.json
   ```

2. **Or keep credentials but remove the helper**:
   ```bash
   cat ~/.docker/config.json | jq 'del(.credsStore)' > ~/.docker/config.json.tmp
   mv ~/.docker/config.json.tmp ~/.docker/config.json
   ```

3. **Re-authenticate if needed**:
   ```bash
   docker login ghcr.io
   ```

### Prevention

- Don't rely on Docker Desktop's credential store for CI/automation
- Use environment variables or Docker secrets for registry credentials
- Consider using `credHelpers` for specific registries instead of global `credsStore`

---

## WSL2 Socket Communication Errors

### Symptom

```
UtilAcceptVsock:271: accept4 failed 110
```

Or intermittent connection drops during builds.

### Cause

Docker Desktop's WSL2 integration uses virtual sockets (vsock) to communicate between the Windows host and WSL2. These can be unstable under heavy load or when Docker Desktop is in a degraded state.

### Solution

1. **Restart Docker Desktop**:
   - Right-click Docker Desktop icon in system tray
   - Select "Restart"

2. **Restart WSL2** (if Docker Desktop restart doesn't help):
   ```powershell
   # In PowerShell (Windows)
   wsl --shutdown
   ```
   Then reopen your WSL2 terminal.

3. **Check Docker Desktop status**:
   ```bash
   docker info
   docker version
   ```

4. **Increase resources** in Docker Desktop settings:
   - Memory: 4GB minimum, 8GB recommended
   - CPUs: 2 minimum, 4 recommended
   - Disk image size: 64GB minimum

### Prevention

- Keep Docker Desktop updated
- Avoid running too many concurrent builds
- Use BuildKit's `--max-parallelism` flag for complex builds

---

## Build Context Too Large

### Symptom

```
#11 transferring context: 44.72GB 446.4s done
```

Build times are excessive, and builds may timeout or fail with connection errors.

### Cause

Missing or incomplete `.dockerignore` file causes Docker to send the entire repository (including venv, node_modules, .git, etc.) as build context.

### Solution

1. **Create/update `.dockerignore`** in repository root:
   ```
   # Virtual environments
   aods_venv/
   venv/
   .venv/

   # Git
   .git/

   # Node modules
   node_modules/
   design/ui/react-app/node_modules/

   # Python cache
   __pycache__/
   *.py[cod]

   # Large outputs
   artifacts/
   reports/
   *.apk
   ```

2. **Verify context size before build**:
   ```bash
   # Estimate what Docker will send
   du -sh --exclude='.git' --exclude='aods_venv' --exclude='node_modules' .
   ```

3. **For this project**, the `.dockerignore` should reduce context from ~44GB to <500MB.

### Prevention

- Always include `.dockerignore` in repository root
- Review `.dockerignore` when adding new large directories
- Use multi-stage builds to avoid needing large source trees

---

## BuildKit Syntax Directive Failures

### Symptom

```
failed to solve: failed to resolve source metadata for docker.io/docker/dockerfile:1.6
```

### Cause

Dockerfiles with `# syntax=docker/dockerfile:1.6` at the top require BuildKit to pull this image, which can fail if:
- Network is unavailable
- Credential store is broken (see above)
- The syntax image version doesn't exist

### Solution

1. **Remove the syntax directive** from your Dockerfile:
   ```dockerfile
   # Remove this line:
   # syntax=docker/dockerfile:1.6

   # Keep your actual build instructions:
   FROM python:3.11-slim
   ...
   ```

2. **Or pin to a known-working version**:
   ```dockerfile
   # syntax=docker/dockerfile:1.5
   ```

3. **Use local BuildKit features without directive**:
   BuildKit features like `--mount=type=cache` work without the syntax directive in modern Docker versions (20.10+).

### Prevention

- Only use syntax directives when you need bleeding-edge Dockerfile features
- Pin to stable versions if you must use them
- Test builds in clean environments before committing

---

## gRPC Connection Errors

### Symptom

```
rpc error: code = Unavailable desc = error reading from server: EOF
rpc error: code = Canceled desc = grpc: the client connection is closing
```

### Cause

BuildKit daemon connection dropped, usually due to:
- Docker Desktop instability
- Timeout during large context transfer
- Memory pressure on the build daemon

### Solution

1. **Retry the build** - cached layers will be reused:
   ```bash
   docker compose --profile dev build api-ui
   ```

2. **Restart Docker if retries fail**:
   ```bash
   # From WSL2
   docker system prune -f
   # Then restart Docker Desktop from Windows
   ```

3. **Reduce build parallelism**:
   ```bash
   DOCKER_BUILDKIT=1 BUILDKIT_STEP_LOG_MAX_SIZE=-1 docker build \
     --build-arg BUILDKIT_INLINE_CACHE=1 \
     --progress=plain \
     .
   ```

### Prevention

- Keep `.dockerignore` up to date (reduces context transfer time)
- Use BuildKit cache mounts for pip/npm
- Consider using `docker buildx create` with a dedicated builder instance

---

## Quick Reference

| Issue | Quick Fix |
|-------|-----------|
| Credential error | `echo '{}' > ~/.docker/config.json` |
| VSock errors | Restart Docker Desktop |
| Large context | Check `.dockerignore` |
| Syntax directive | Remove `# syntax=...` line |
| gRPC EOF | Retry build (uses cache) |

## Related Documentation

- [Docker Desktop WSL2 Backend](https://docs.docker.com/desktop/wsl/)
- [BuildKit Documentation](https://docs.docker.com/build/buildkit/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
