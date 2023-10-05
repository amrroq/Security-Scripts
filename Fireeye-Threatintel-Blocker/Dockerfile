# syntax=docker/dockerfile:1

FROM alpine:latest
ENV PATH="${PATH}:/opt/app"
COPY getindicators.sh /usr/local/bin/
COPY . /opt/app
RUN set -ex \
    # Create a non-root user
    && addgroup -S -g 1001 appgroup \
    && adduser -S -u 1001 -g 1001 --no-create-home appuser 
    # Upgrade the package index and install security upgrades
RUN apk update && apk add \
    bash \
    ca-certificates \
    curl \
    jq \
    python3 \
    py3-pip \
    && apk del
RUN pip install -r /opt/app/requirements.txt
#ENTRYPOINT ["getindicators.sh"]
#CMD ["--ip-src"]
USER appuser
