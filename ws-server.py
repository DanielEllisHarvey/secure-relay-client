from fastapi import FastAPI, WebSocket, Response
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import os
# from fastapi.responses import HTMLResponse

app = FastAPI()

privateKey = ec.generate_private_key(ec.SECP384R1())
publicKey = base64.b64encode(privateKey.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.named_connections: dict = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        #  self.named_connections

    async def alias(self, name: str, websocket: WebSocket):
        self.named_connections.update({name: websocket})
        self.named_connections.update({websocket: name})

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.get("/keys")
def return_pubkey():
    # response.headers["Content-Type"] = "text/plain"
    return {"p384_server": publicKey}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, key: str):
    await manager.connect(websocket)
    # print(manager.active_connections)
    # await manager.alias(await websocket.receive_text(), websocket)
    print(key)
    bytes_key = base64.b64decode(key.replace(" ", "+"))
    print(bytes_key)
    peer_public_key = serialization.load_der_public_key(bytes_key)
    sharedKey = privateKey.exchange(ec.ECDH(), peer_public_key)[0:32]
    randomBytesChallenge = os.urandom(64)
    await websocket.send_json({"p384key": str(publicKey, "utf-8"), "randomBytesChallenge": str(base64.b64encode(randomBytesChallenge), "utf-8")})
    challengeResponse = await websocket.receive_bytes()
    hashInstance = hmac.HMAC(sharedKey, hashes.SHA512())
    hashInstance.update(randomBytesChallenge)
    digest = hashInstance.finalize()
    if digest == challengeResponse:
        await manager.alias(websocket, key)
    else: websocket.close(reason="Wrong challenge code.")
    while True:
        message = await websocket.receive_json()
        await manager.send_personal_message(base64.b64encode(sharedKey), websocket)
        
            # name = manager.named_connections[websocket]
            # if "body" not in data: await manager.send_personal_message("Error: No body in message body")
            # if (("recipient" in data) and (data["recipient"] in manager.named_connections)):
            #     await manager.send_personal_message(f"{manager.named_connections[websocket]}: {data["body"]}", manager.named_connections[data["recipient"]])
            # else: await manager.send_personal_message("Error: Undefined or invalid recipient in message body", websocket)
        # print(data)