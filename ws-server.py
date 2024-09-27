from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import base64
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
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
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        self.unalias(websocket)
        #  self.named_connections

    def unalias(self, websocket: WebSocket):
        key = self.named_connections[websocket]
        self.named_connections.pop(websocket)
        self.named_connections.pop(key)

    def alias(self, name: str, websocket: WebSocket):
        self.named_connections.update({name: websocket})
        self.named_connections.update({websocket: name})

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
        
    async def send_message_by_key_json(self, message: str, key: str, return_address: WebSocket):
        if key in self.named_connections:
            websocket = self.named_connections[key]
            await websocket.send_json(message)
        await return_address.send_json({"type": "recipientNotFound"})

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)
    
    async def broadcast_json(self, message: str):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

@app.get("/keys")
def return_pubkey():
    # response.headers["Content-Type"] = "text/plain"
    return {"p384_server": publicKey}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, key: str):
    await websocket.accept()
    # print(manager.active_connections)
    # await manager.alias(await websocket.receive_text(), websocket)
    parsed_key = key.replace(" ", "+")
    bytes_key = base64.b64decode(parsed_key)
    peer_public_key = serialization.load_der_public_key(bytes_key)
    sharedKey = privateKey.exchange(ec.ECDH(), peer_public_key)[0:32]
    randomBytesChallenge = os.urandom(1024)
    await websocket.send_json({"type": "challenge", "p384key": str(publicKey, "utf-8"), "randomBytesChallenge": str(base64.b64encode(randomBytesChallenge), "utf-8")})
    challengeResponse = await websocket.receive_bytes()
    hashInstance = hmac.HMAC(sharedKey, hashes.SHA512())
    hashInstance.update(randomBytesChallenge)
    digest = hashInstance.finalize()
    if digest == challengeResponse:
        manager.alias(websocket,parsed_key)
        await manager.connect(websocket)
        print("challenge complete")
        print(manager.named_connections)
    # else: websocket.close(reason="Wrong challenge code.")
    # while text != "ready": text = await websocket.receive_text()
    try:
        while True:
            message = await websocket.receive_json()
            print(message)
            await manager.send_message_by_key_json(message, message["to"], websocket)
            # await manager.send_personal_message(base64.b64encode(sharedKey), websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        