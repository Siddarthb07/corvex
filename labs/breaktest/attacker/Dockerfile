FROM python:3.11-slim
WORKDIR /attack
RUN pip install --no-cache-dir requests==2.32.3
COPY art_attack.py .
CMD ["python", "-u", "art_attack.py"]
