# The auth lane's Morpheus pipeline (auth_pipeline.py) as a service.
#
# The image holds only this project's code. The Morpheus runtime is the VM's
# existing conda env (SETUP §7), bind-mounted read-only at the same path by
# ai-stack.yml — conda envs carry absolute paths, so the path must match. NVIDIA's
# official image (nvcr.io/nvidia/morpheus/morpheus:25.06-runtime) needs an NGC
# login to pull; this needs nothing new. The GPU and its driver come from the
# NVIDIA container runtime (`deploy.resources` in ai-stack.yml).
#
# Ubuntu 24.04 = the VM's own OS, so the env finds the same glibc it was built on.
FROM ubuntu:24.04
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY ai-stack/pipeline/ ai-stack/pipeline/
COPY ai-stack/morpheus/ ai-stack/morpheus/
