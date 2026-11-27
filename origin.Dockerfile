FROM python:3.12-alpine
WORKDIR /lab
COPY origin.py .
USER nobody
EXPOSE 8081
CMD ["python", "-u", "origin.py"]
