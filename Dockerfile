FROM python:3

ADD check_pve.py /
ADD requirements.txt /
RUN apt-get update
RUN apt install -y python3 python3-requests python3-packaging
RUN pip3 install -r requirements.txt


CMD ["tail", "-f", "/dev/null"]
