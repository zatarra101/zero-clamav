FROM clamav/clamav:1.4-debian13-slim

COPY scanner/run-poc.sh /usr/local/bin/run-poc.sh
RUN chmod +x /usr/local/bin/run-poc.sh

ENTRYPOINT ["/usr/local/bin/run-poc.sh"]
