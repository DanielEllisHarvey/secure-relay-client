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
        self.clients_online: dict = {}

    async def connect(self, websocket: WebSocket):
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        self.unalias(websocket)
        #  self.named_connections

    def unalias(self, websocket: WebSocket):
        key = self.named_connections[websocket]
        # self.clients_online.pop(key)
        self.named_connections.pop(websocket)
        self.named_connections.pop(key)

    def alias(self, bytes_key: str, websocket: WebSocket):
        hashInstance = hashes.Hash(hashes.SHA256())
        hashInstance.update(bytes_key)
        digest = hashInstance.finalize()[0:12]
        name = str(base64.b64encode(digest), "utf-8")
        self.named_connections.update({name: websocket})
        self.named_connections.update({websocket: name})
        
    def add_key(self, bytes_key: str):
        hashInstance = hashes.Hash(hashes.SHA256())
        hashInstance.update(bytes_key)
        digest = hashInstance.finalize()[0:12]
        name = str(base64.b64encode(digest), "utf-8")
        key = str(base64.b64encode(bytes_key), "utf-8")
        self.clients_online.update({name: key})

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
        
    async def send_message_by_key_json(self, message: str, key: str, return_address: WebSocket):
        if key in self.named_connections:
            websocket = self.named_connections[key]
            await websocket.send_json(message)
        elif message["action"] != "hello": await return_address.send_json({"type": "recipientNotFound"})

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)
    
    async def broadcast_json(self, message: str):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

@app.websocket("/register")
async def register_key(websocket: WebSocket, key: str | None = None, n: int | int = 0):
    await websocket.accept()
    if key != None:
        parsed_key = key.replace(" ", "+")
        bytes_key = base64.b64decode(parsed_key)
        manager.add_key(bytes_key)
    if n >= len(manager.clients_online):
        await websocket.close()
        return
    await websocket.send_json(manager.clients_online)
    await websocket.close()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, id: str):
    await websocket.accept()
    # print(manager.active_connections)
    # await manager.alias(await websocket.receive_text(), websocket)
    parsed_key = id.replace(" ", "+")
    parsed_key = manager.clients_online[parsed_key]
    bytes_key = base64.b64decode(parsed_key)
    manager.add_key(bytes_key)
    peer_public_key = serialization.load_der_public_key(bytes_key)
    
    sharedKey = privateKey.exchange(ec.ECDH(), peer_public_key)[0:32]
    randomBytesChallenge = os.urandom(64)
    await websocket.send_json({"type": "challenge", "p384key": str(publicKey, "utf-8"), "randomBytesChallenge": str(base64.b64encode(randomBytesChallenge), "utf-8")})
    
    challengeResponse = await websocket.receive_bytes()
    hashInstance = hmac.HMAC(sharedKey, hashes.SHA512())
    hashInstance.update(randomBytesChallenge)
    digest = hashInstance.finalize()
    if digest == challengeResponse:
        print(str(base64.b64encode(digest), "utf-8"))
        manager.alias(bytes_key, websocket)
        await manager.connect(websocket)
        print("challenge complete")
        print(manager.named_connections)
    else: websocket.close(reason="Wrong challenge code.")
    # while text != "ready": text = await websocket.receive_text()
    try:
        # await websocket.send_json(manager.clients_online)
        while True:
            message = await websocket.receive_json()
            print(message)
            if message["action"] == "msg":
                await manager.send_message_by_key_json(message, message["to"], websocket)
            if message["action"] == "hello":
                await manager.send_message_by_key_json(message, message["to"], websocket)
            # await manager.send_personal_message(base64.b64encode(sharedKey), websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        