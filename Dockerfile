FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
ENV BASE_DIR=/opt/configuration-guardian

WORKDIR ${BASE_DIR}

RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    gzip \
    file \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask

RUN mkdir -p config data/storage data/index logs templates

COPY app.py .
COPY templates/ ./templates/

RUN chmod +x app.py

EXPOSE 8080

CMD ["python", "app.py"]
