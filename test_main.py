import os
import sys
import sqlite3
import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import app, DB_NAME

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users;")
        cursor.execute("DELETE FROM user_events;")
        conn.commit()


def get_auth_headers(email, password):

    client.post("/api/auth/register", json={"email": email, "password": password})
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    token = response.json().get("token")
    return {"Authorization": f"Bearer {token}"}


def test_1_register_success():

    response = client.post("/api/auth/register", json={"email": "tester@example.com", "password": "password123"})
    assert response.status_code == 200
    assert response.json() == {"message": "Регистрация успешно завершена!"}


def test_2_register_duplicate_username():

    client.post("/api/auth/register", json={"email": "duplicate@example.com", "password": "password123"})
    response = client.post("/api/auth/register", json={"email": "duplicate@example.com", "password": "password123"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Этот email уже используется."


def test_3_login_success():

    client.post("/api/auth/register", json={"email": "login@example.com", "password": "password123"})
    response = client.post("/api/auth/login", json={"email": "login@example.com", "password": "password123"})
    assert response.status_code == 200
    assert "token" in response.json()


def test_4_login_invalid_credentials():

    client.post("/api/auth/register", json={"email": "wrongpass@example.com", "password": "password123"})
    response = client.post("/api/auth/login", json={"email": "wrongpass@example.com", "password": "incorrect_password"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Неверная почта или пароль."



def test_5_create_event():

    headers = get_auth_headers("user1@example.com", "password123")
    payload = {"title": "Лабораторная работа", "event_date": "2026-11-20"}
    response = client.post("/api/events", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["title"] == "Лабораторная работа"
    assert "id" in response.json()


def test_6_get_all_user_events():

    headers = get_auth_headers("user2@example.com", "password123")
    client.post("/api/events", json={"title": "Событие А", "event_date": "2026-11-10"}, headers=headers)
    client.post("/api/events", json={"title": "Событие Б", "event_date": "2026-11-12"}, headers=headers)

    response = client.get("/api/events", headers=headers)
    assert response.status_code == 200

    user_events = [item for item in response.json() if item["type"] == "custom"]
    assert len(user_events) == 2


def test_7_get_events_includes_holidays():

    headers = get_auth_headers("user3@example.com", "password123")
    response = client.get("/api/events", headers=headers)
    assert response.status_code == 200

    holidays = [item for item in response.json() if item["type"] == "holiday"]
    assert len(holidays) >= 8
    assert holidays[0]["title"] == "Новый год"


def test_8_validation_error_on_wrong_date_format():

    headers = get_auth_headers("user4@example.com", "password123")
    invalid_payload = {"title": "Ошибка формата", "event_date": "31-12-2026"}
    response = client.post("/api/events", json=invalid_payload, headers=headers)
    assert response.status_code == 422


def test_9_delete_event_success():

    headers = get_auth_headers("user5@example.com", "password123")
    created_event = client.post("/api/events", json={"title": "Удалить", "event_date": "2026-11-15"},
                                headers=headers).json()

    response = client.delete(f"/api/events/{created_event['id']}", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"message": "Событие удалено."}


def test_10_delete_nonexistent_event():

    headers = get_auth_headers("user6@example.com", "password123")
    response = client.delete("/api/events/99999", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Событие не найдено."



def test_11_unauthorized_access_rejected():

    response = client.get("/api/events")
    assert response.status_code == 401


def test_12_read_foreign_events_isolated():

    headers_owner = get_auth_headers("owner@example.com", "password123")
    headers_stranger = get_auth_headers("stranger@example.com", "password123")

    client.post("/api/events", json={"title": "Секретное событие", "event_date": "2026-11-15"}, headers=headers_owner)

    response = client.get("/api/events", headers=headers_stranger)
    stranger_custom_events = [item for item in response.json() if item["type"] == "custom"]
    assert len(stranger_custom_events) == 0


def test_13_delete_foreign_event_forbidden():

    headers_owner = get_auth_headers("owner2@example.com", "password123")
    headers_stranger = get_auth_headers("stranger2@example.com", "password123")

    event = client.post("/api/events", json={"title": "Запись владельца", "event_date": "2026-11-15"},
                        headers=headers_owner).json()

    response = client.delete(f"/api/events/{event['id']}", headers=headers_stranger)
    assert response.status_code == 404
    assert response.json()["detail"] == "Событие не найдено."


def test_14_expired_or_invalid_token():

    bad_headers = {"Authorization": "Bearer invalid_token_string_value_123"}
    response = client.get("/api/events", headers=bad_headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Неверный или устаревший токен сессии"
