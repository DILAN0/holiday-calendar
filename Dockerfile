FROM python:3.8

WORKDIR /app

# Установка системных зависимостей для проекта
RUN pip install --no-cache-dir fastapi uvicorn bcrypt pyjwt pydantic httpx pytest

# Копирование всех файлов из репозитория внутрь контейнера
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
