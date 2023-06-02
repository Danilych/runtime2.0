FROM python:2.7.18

WORKDIR /vdomapp

COPY . .

ENV PORT=8000

EXPOSE 8000

WORKDIR /vdomapp/sources

CMD ["./start.sh"]