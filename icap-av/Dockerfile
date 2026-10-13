# ICAP antivirus service: c-icap + virus_scan module + ClamAV engine (libclamav, in-process).
# BIG-IP Advanced WAF sends uploaded files here (ICAP REQMOD, URI /reqmod, port 1344).
FROM docker.io/library/debian:bookworm-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends c-icap libc-icap-mod-virus-scan clamav-freshclam ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/c-icap /var/log/c-icap /var/lib/clamav \
 && chown -R c-icap /run/c-icap /var/log/c-icap /var/lib/clamav
COPY c-icap.conf /etc/c-icap/c-icap.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER c-icap
EXPOSE 1344
ENTRYPOINT ["/entrypoint.sh"]
