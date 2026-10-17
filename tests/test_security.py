import pytest
from app import app, restrict_ip
from flask import request

@app.route('/test_ip')
@restrict_ip(['192.168.1.100'])
def route_test_ip():
    return "OK", 200

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_restrict_ip_allowed(client):
    response = client.get('/test_ip', environ_base={'REMOTE_ADDR': '192.168.1.100'})
    assert response.status_code == 200
    assert response.data == b"OK"

def test_restrict_ip_blocked(client):
    response = client.get('/test_ip', environ_base={'REMOTE_ADDR': '192.168.1.101'})
    # It returns go_back() which is `<script>window.history.back();</script>`, 200
    assert response.status_code == 200
    assert b"<script>window.history.back();</script>" in response.data
