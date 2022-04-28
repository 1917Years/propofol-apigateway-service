FROM openjdk:11-jdk

WORKDIR /server

COPY ./build/libs/*-SNAPSHOT.jar app.jar

ENTRYPOINT ["java","-jar","app.jar"]