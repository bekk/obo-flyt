FROM python:3.9

WORKDIR /app

COPY . .

RUN pip install --upgrade -r ./requirements.txt

CMD ["fastapi", "run", "main.py", "--port", "3000", "--reload"]
