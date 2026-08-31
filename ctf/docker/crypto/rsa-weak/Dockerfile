# T3MP3ST CTF Challenge: RSA - Weak Prime Factor
# Difficulty: Easy (1)
# Category: Cryptography

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors

# Create vulnerable application (constants baked in at generation time)
COPY app.py /app/

# Set environment variables
ENV FLASK_APP=app.py
ENV CTF_FLAG=T3MP3ST{w34k_rs4_pr1m3_f4ct0r}

EXPOSE 80

CMD ["python", "app.py"]
