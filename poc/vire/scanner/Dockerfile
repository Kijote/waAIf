FROM python:3.12-alpine
WORKDIR /app
COPY scan.py /app/scan.py
USER 65534:65534
ENTRYPOINT ["python", "/app/scan.py"]
