FROM node:alpine
WORKDIR /app
COPY out/ /app
RUN npm install -g serve
EXPOSE 3000
CMD ["serve","-s","/app","-l","3000"]
