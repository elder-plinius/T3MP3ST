# T3MP3ST CTF Challenge: Blind SQL Injection - Data Extraction
# Difficulty: Medium (2)
# Category: Web Exploitation

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors

# Create vulnerable application
COPY app.py /app/

# Set environment variables
ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{bl1nd_sql1_t1m3_b4s3d}

EXPOSE 80

CMD ["python", "app.py"]
