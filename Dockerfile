FROM debian:buster-slim

RUN echo "deb http://deb.debian.org/debian/ sid main" >> /etc/apt/sources.list
RUN echo "APT::Default-Release stable;" > /etc/apt/apt.conf.d/default-release
RUN export DEBIAN_FRONTEND=noninteractive && apt update && apt install -y -t sid bird2 procps iproute2

RUN mkdir -p /run/bird/ && touch /run/bird/bird.ctl

CMD [ "bird", "-d" ]
