# syntax = docker/dockerfile:1.3
FROM python:3.8-slim
RUN pip3 install elasticsearch
RUN pip3 install datetime
RUN pip3 install urllib3
RUN pip3 install argparse
ADD shibb.py /
CMD python shibb.py now-3h now -s 10000