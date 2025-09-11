# secscan-ui/Dockerfile
# 1) Build aşaması
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
# VITE build (API base'i UI’dan kullanmayacağız; Nginx /api'ye proxy verecek)
RUN npm run build

# 2) Runtime: nginx
FROM nginx:1.27-alpine
# Statik dosyaları kopyala
COPY --from=build /app/dist /usr/share/nginx/html
# Nginx konfigürasyonunu ekle
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

