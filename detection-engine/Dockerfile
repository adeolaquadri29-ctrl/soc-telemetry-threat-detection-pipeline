FROM ubuntu:22.04

WORKDIR /app

RUN apt update && apt install -y 
python3 
python3-pip 
python3-elasticsearch 
python3-requests

COPY enrich_ip.py .

CMD [“python3”, “enrich_ip.py”]
