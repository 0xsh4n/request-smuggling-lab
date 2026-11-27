FROM python:3.12-alpine
WORKDIR /lab
COPY proxy.py .
USER nobody
EXPOSE 8080
CMD ["python", "-u", "proxy.py"]
