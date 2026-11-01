# CADMUS VulnBank mock backend - training image (sandbox only)
FROM python:3.12-slim
WORKDIR /srv/vulnbank
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV PORT=8080
EXPOSE 8080
# Runs as an unprivileged user; the app itself is deliberately weak.
RUN useradd --system --uid 10001 vulnbank
USER vulnbank
CMD ["python", "app.py"]
