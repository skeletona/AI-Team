FROM benyamin/codex-sandbox:latest

RUN apt update
RUN apt install -y vim python3-pip python3-requests locales python3-dotenv netcat-openbsd iputils-ping sudo file python-is-python3 binwalk

RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV LANGUAGE=en_US:en

RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/ubuntu \
 && chmod 0440 /etc/sudoers.d/ubuntu
USER 1000:1000

COPY python/instance.py /usr/local/sbin/instance
