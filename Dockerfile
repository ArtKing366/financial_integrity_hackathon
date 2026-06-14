FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY signalshield/requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY signalshield/ ./

RUN useradd --create-home --shell /bin/sh signalshield \
    && mkdir -p /app/runtime \
    && chown -R signalshield:signalshield /app /home/signalshield

USER signalshield

EXPOSE 8501 8766

CMD ["python", "api_server.py", "--host", "0.0.0.0", "--port", "8766"]
