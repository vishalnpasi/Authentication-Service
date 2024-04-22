FROM 851796746980.dkr.ecr.us-west-2.amazonaws.com/albanero.base_java_repo:latest
WORKDIR /app
COPY / /app

RUN chmod +x /app/service-deploy.sh

RUN gradle clean build -x test

EXPOSE 9020

ENTRYPOINT ["sh","/app/service-deploy.sh"]


