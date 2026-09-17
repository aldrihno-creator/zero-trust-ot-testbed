FROM python:3.12-slim
WORKDIR /app
COPY modbus_pep.py policy.json /app/
EXPOSE 5020
CMD ["python3", "modbus_pep.py"]
