FROM golang:1.23.5

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o vulnscan

EXPOSE 8080

CMD ["./vulnscan"]