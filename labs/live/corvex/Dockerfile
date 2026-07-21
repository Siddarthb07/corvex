FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir typer cryptography
# corvex mounted at runtime from repo
ENV PYTHONPATH=/app
COPY defend.py /defend.py
CMD ["python", "-u", "/defend.py"]
