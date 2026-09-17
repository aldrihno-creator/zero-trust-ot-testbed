FROM python:3.12-slim
WORKDIR /app
COPY modbus_pep_v2.py /app/modbus_pep.py
COPY policy_v2.json /app/policy.json
EXPOSE 5020
CMD ["python3", "modbus_pep.py"]
