FROM python:3.11-slim
WORKDIR /attack
RUN pip install --no-cache-dir requests==2.32.3
COPY attack.py .
CMD ["python", "-u", "attack.py"]
