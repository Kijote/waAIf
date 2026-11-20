FROM python:3.12-alpine
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY scan.py inventory.py reconcile.py sbom.py signature.py /app/
USER 65534:65534
ENTRYPOINT ["python", "/app/scan.py"]
