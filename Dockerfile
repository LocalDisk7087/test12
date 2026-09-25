# Deliberately the lightest possible base - no Playwright, no pip installs,
# no extra OS packages - to make sure nothing about seo-keyword-checker's
# heavier image is what's causing the outbound hang.
FROM python:3.12-slim

WORKDIR /app
COPY app.py .

EXPOSE 8080

CMD ["python3", "app.py"]
