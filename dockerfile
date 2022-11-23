FROM ubuntu:latest

WORKDIR /usr/src/app

EXPOSE 3123

RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y

COPY main.py ./
COPY contexts.py ./
COPY blockchain.py ./
COPY networking.py ./
COPY tests.py ./

COPY config.yml ./
COPY requirements.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["/bin/python3", "main.py"]
