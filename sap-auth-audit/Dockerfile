FROM python:3.12-slim
WORKDIR /app
COPY sapauth ./sapauth
COPY sample_data ./sample_data
ENTRYPOINT ["python", "-m", "sapauth"]
CMD ["--data", "sample_data", "--out", "out", "--today", "2026-10-15"]