FROM openjdk:17-alpine

RUN apk add --no-cache freetype fontconfig ttf-dejavu

WORKDIR /app


COPY target/Hizam-0.0.1-SNAPSHOT.jar myapp.jar


EXPOSE 8086


ENTRYPOINT ["java", "-jar", "myapp.jar"]