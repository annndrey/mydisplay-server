FROM python:3.6-alpine

RUN adduser -D realestate

WORKDIR /home/realestate

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install gunicorn

COPY migrations migrations
COPY postcodes.csv ./
COPY app.py models.py config_dev.py boot.sh ./
RUN chmod +x boot.sh

ENV FLASK_APP app.py
ENV APPSETTINGS config_dev.py
ENV DEFAULTUSER realestateuser
ENV DEFAULTPASSWORD ChangeMeLater
RUN chown -R realestate:realestate ./
RUN echo "HELLO"
RUN ls -latr .
USER realestate

EXPOSE 5000
ENTRYPOINT ["./boot.sh"]