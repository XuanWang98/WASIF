FROM ubuntu:18.04
From python:3.6.9

RUN apt update && \
    apt install -y software-properties-common sudo curl wget python vim libncurses5 psmisc libusb-1.0-0 && \
    rm -rf /*.deb /var/lib/apt/lists/* 

RUN mkdir -p /home/wx/LOGS && \
    mkdir -p /home/wx/wasif

COPY . /home/wx/wasif

WORKDIR /home/wx/wasif

RUN mv ./instrumentation/* /usr/bin/ && \
    python3 -m pip install -r ./requirements.txt

ENTRYPOINT ["/bin/bash"]