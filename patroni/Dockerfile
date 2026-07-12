FROM postgres:16

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-psycopg2 \
      curl wget gosu \
 && pip3 install --no-cache-dir --break-system-packages \
      "patroni[etcd3]" \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY bootstrap.yml  /etc/patroni/bootstrap.yml

RUN chmod +x /entrypoint.sh

EXPOSE 5432 8008

ENTRYPOINT ["/entrypoint.sh"]
