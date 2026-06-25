FROM node:18-bullseye

ENV NODE_ENV=production
WORKDIR /app

# Build tools for native modules such as sqlite3 and bcrypt
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    pkg-config \
    sqlite3 \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install --omit=dev --no-audit --no-fund --foreground-scripts \
  && npm rebuild sqlite3 --build-from-source --foreground-scripts \
  && test -f node_modules/sqlite3/build/Release/node_sqlite3.node

COPY . .

EXPOSE 3000
CMD ["npm", "start"]
