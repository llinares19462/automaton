import os
import random
import string
import json
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from typing import List, Dict

# Puerto en el que escuchará el servidor HTTP
PORT = 8080

# Lista de usuarios autorizados con su ID de Telegram y token de autenticación
AUTHORIZED_USERS = [
    {"user_id": 123456789, "auth_token": "random_token_1"},
    {"user_id": 987654321, "auth_token": "random_token_2"}
]

# Clase que maneja las solicitudes del servidor HTTP
class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("content-length"))
        body = self.rfile.read(content_length)
        data = json.loads(body)

        # Comprobar que la solicitud proviene de Telegram
        if self.is_valid_telegram_request(data):
            # Procesar el mensaje si proviene de un usuario autorizado
            if self.is_authorized_user(data):
                self.handle_message(data)
                self.send_response(200)
                self.end_headers()
            else:
                self.send_error(401, "Unauthorized")
        else:
            self.send_error(400, "Bad Request")

    def is_valid_telegram_request(self, data: Dict) -> bool:
        # Comprobar que la solicitud proviene de Telegram utilizando la clave secreta configurada
        telegram_secret_key = os.environ.get("TELEGRAM_SECRET_KEY")
        if telegram_secret_key:
            data_bytes = json.dumps(data).encode("utf-8")
            hash_code = hashlib.sha256(telegram_secret_key.encode("utf-8") + data_bytes).hexdigest()
            return hash_code == self.headers.get("X-Telegram-Hash")
        else:
            return False

    def is_authorized_user(self, data: Dict) -> bool:
        # Comprobar si el usuario que ha enviado el mensaje está en la lista de usuarios autorizados
        user_id = data.get("message", {}).get("from", {}).get("id")
        auth_token = self.get_auth_token_for_user(user_id)
        if auth_token:
            return data.get("message", {}).get("text") is not None and data.get("message", {}).get("text") != ""
        else:
            return False

    def get_auth_token_for_user(self, user_id: int) -> str:
        # Obtener el token de autenticación del usuario correspondiente
        for user in AUTHORIZED_USERS:
            if user["user_id"] == user_id:
                return user["auth_token"]
        return ""

    def handle_message(self, data: Dict):
        # Procesar el mensaje y enviar una respuesta utilizando el token de autenticación del usuario correspondiente
        user_id = data["message"]["from"]["id"]
        text = data["message"]["text"]
        auth_token = self.get_auth_token_for_user(user_id)
        self.send_message(text, user_id, auth_token)

    def send_message(self, text: str, chat_id: int, auth_token: str):
        # Enviar un mensaje utilizando el token de autenticación
        url = f"https://api.telegram.org/bot{auth_token}/sendMessage"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {"chat_id": chat_id, "text": text}
        encoded_data = parse_qs(json.dumps(data))
        http_conn = HTTP
