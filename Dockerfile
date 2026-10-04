# Public single-service deployment image: build the dashboard, then serve it
# together with the FastAPI API. Local development continues to use Compose.
FROM node:22-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=10000
WORKDIR /app
RUN addgroup --gid 10001 --system bayora && adduser --uid 10001 --system --ingroup bayora --home /app bayora
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./
COPY --from=frontend-build /frontend/dist ./app/static
RUN mkdir /data && chown -R bayora:bayora /app /data
USER bayora
EXPOSE 10000
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
