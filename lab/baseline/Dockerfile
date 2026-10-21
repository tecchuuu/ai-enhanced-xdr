# Wraps the baseline generator so it survives a VM reboot (restart policy) like
# the rest of the stack (failure log Entry 35). Pure stdlib -> no pip install.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY lab_baseline.py .
ENTRYPOINT ["python", "lab_baseline.py"]
