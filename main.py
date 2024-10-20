from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import secrets
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
import base64

app = FastAPI()

client = AsyncIOMotorClient("mongodb://mongodb:27017")
db = client.secrets_db
secrets_collection = db.secrets

class SecretCreate(BaseModel):
    secret: str
    passphrase: str 
    ttl: Optional[int] = None # Time to live in seconds

class SecretResponse(BaseModel):
    secret_key: str

class SecretRetrieve(BaseModel):
    passphrase: str

def xor_encrypt_decrypt(text: str, key: str) -> str:
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key * (len(text) // len(key) + 1)))

async def get_secret(secret_key: str):
    secret = await secrets_collection.find_one({"secret_key": secret_key})
    if secret is None:
        raise HTTPException(status_code=404, detail='Secret not found')
    return secret

@app.post('/generate', response_model=SecretResponse)
async def generate_secret(secret_data: SecretCreate):
    """
    Generate a new secret and return a secret key.

    Args:
        secret_data (SecretCreate): The secret data including the secret itself and a passphrase.

    Returns:
        SecretResponse: The generated secret key.
    """
    secret_key = secrets.token_urlsafe(16)
    encrypted_secret = xor_encrypt_decrypt(secret_data.secret, secret_data.passphrase)
    encoded_secret = base64.b64encode(encrypted_secret.encode()).decode()
    hashed_passphrase = bcrypt.hashpw(secret_data.passphrase.encode(), bcrypt.gensalt())

    expiration_date = None
    if secret_data.ttl:
        expiration_date = datetime.utcnow() + timedelta(seconds=secret_data.ttl)

    await secrets_collection.insert_one({
        'secret_key': secret_key,
        'secret': encoded_secret,
        'passphrase': hashed_passphrase,
        'expiration_date': expiration_date
    })

    return SecretResponse(secret_key=secret_key)

@app.post('/secrets/{secret_key}', response_model=str)
async def retrieve_secret(secret_key: str, secret_retrieve: SecretRetrieve):
    """
    Retrieve a secret using the secret key and passphrase.

    Args:
        secret_key (str): The secret key generated during secret creation.
        secret_retrieve (SecretRetrieve): The passphrase to retrieve the secret.

    Returns:
        str: The retrieved secret.
    """
    secret = await get_secret(secret_key)

    if bcrypt.checkpw(secret_retrieve.passphrase.encode(), secret['passphrase']):
        if secret.get('expiration_date') and datetime.utcnow() > secret['expiration_date']:
            await secrets_collection.delete_one({'secret_key': secret_key})
            raise HTTPException(status_code=404, detail='Secret has expired')
        
        encoded_secret = secret['secret']
        encrypted_secret = base64.b64decode(encoded_secret).decode()
        decrypted_secret = xor_encrypt_decrypt(encrypted_secret, secret_retrieve.passphrase)
        await secrets_collection.delete_one({'secret_key': secret_key})
        return decrypted_secret
    else:
        raise HTTPException(status_code=403, detail='Invalid passphrase')

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)