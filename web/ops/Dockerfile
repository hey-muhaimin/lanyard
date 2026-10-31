FROM node:alpine
WORKDIR /app
COPY out/ /app
RUN npm install -g serve
EXPOSE 4000
CMD ["serve","-s","/app","-l","4000"]
