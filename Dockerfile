FROM node:24-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --ignore-scripts

COPY src ./src
COPY tsconfig.json ./

RUN mkdir -p /app/data

ENV PORT=3000
EXPOSE 3000

CMD ["node", "src/index.ts"]
