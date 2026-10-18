# One image for the API + console and both detectors; ai-stack/ai-stack.yml
# runs it three times with different commands. Paths inside mirror the repo, so
# the code finds dashboard/.env (bind-mounted at run time, never baked in)
# where it does on the host. Build context = repo root; .dockerignore keeps it
# to the files used here.

# --- console: build the React app ---
FROM node:22-slim AS console
WORKDIR /src
COPY dashboard/frontend/package.json dashboard/frontend/package-lock.json ./
RUN npm ci
COPY dashboard/frontend/ ./
RUN npm run build

# --- runtime: the API and the detectors ---
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ai-stack/pipeline/ ai-stack/pipeline/
COPY dashboard/ dashboard/
COPY --from=console /src/dist/ dashboard/frontend/dist/
