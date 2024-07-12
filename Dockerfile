# syntax=docker/dockerfile:1

FROM python:3.10-slim-bullseye

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

EXPOSE 4000

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=4000"]