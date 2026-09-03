FROM alpine:3.19

RUN apk add --no-cache \
    postfix \
    postfix-pcre \
    python3 \
    ca-certificates \
    bash \
    tzdata \
    mailx

COPY entrypoint.sh /entrypoint.sh
COPY log_forwarder.py /log_forwarder.py
COPY dashboard.py /dashboard.py

RUN chmod +x /entrypoint.sh /log_forwarder.py /dashboard.py

EXPOSE 25 587 443

ENTRYPOINT ["/entrypoint.sh"]
