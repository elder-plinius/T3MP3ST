# T3MP3ST CTF Challenge: Memory Forensics - Credential Extraction
# Difficulty: Medium (2)
# Category: Forensics

FROM python:3.11-slim

WORKDIR /srv

# Install dependencies
RUN pip install flask flask-cors

# Artifact arrives via the compose volume mount (./challenges/artifacts:/data:ro)
COPY app.py /srv/

ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{v0l4t1l1ty_m3m0ry_dump}

EXPOSE 80

CMD ["python", "app.py"]
