FROM openjdk:17-jdk-alpine

COPY flag.txt /flag.txt

WORKDIR /app

COPY build/ .

CMD ["java","-jar","/app/libs/ice-0.0.1-SNAPSHOT.jar"]
