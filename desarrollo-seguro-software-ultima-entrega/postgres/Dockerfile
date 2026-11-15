FROM postgres:16-alpine
COPY certs/db.crt /etc/postgresql/certs/db.crt
COPY certs/db.key /etc/postgresql/certs/db.key
COPY postgres/pg_hba.conf /etc/postgresql/pg_hba.conf
RUN chown postgres:postgres /etc/postgresql/certs/db.* \
    && chmod 0600 /etc/postgresql/certs/db.key \
    && chmod 0644 /etc/postgresql/certs/db.crt /etc/postgresql/pg_hba.conf
