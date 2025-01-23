FROM python:3.13

WORKDIR /app

COPY ./requirements.txt .

RUN pip install --upgrade -r ./requirements.txt

COPY ./*.json .
COPY ./*.py .

CMD ["fastapi", "run", "main.py", "--port", "6348", "--reload"]
