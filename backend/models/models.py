from cryptography.fernet import Fernet
from sqlalchemy import Column, Integer, String, UUID
from database import Base
import uuid

def decrypt(value):
        from routes.v1.shared_methods import decrypt, load_private_key
        return decrypt(value, load_private_key())

class User(Base):
    
    __tablename__ = "users"

    id = Column(UUID, primary_key=True, index=True)
    username = Column(String, index=True)  # ENCRYPTED

    def to_dict(self):
        return {
            "id": str(self.id),
            "username": decrypt(self.username)
        }

class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID, primary_key=True, index=True)
    user_id = Column(UUID, index=True) 
    value = Column(String)  # ENCRYPTED

    def decrypt_username(self):
        from routes.v1.shared_methods import decrypt, load_private_key
        return decrypt(self.username, load_private_key())

    def to_dict(self):
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "value": decrypt(self.value)  
        }

class Secret(Base):
    __tablename__ = "secrets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = Column(String, index=True)  # ENCRYPTED
    user_id = Column(UUID)  
    token_id = Column(UUID) 
    name = Column(String)  # ENCRYPTED
    description = Column(String)  # ENCRYPTED

    def to_dict(self):
        return {
            "id": str(self.id),
            "value": decrypt(self.value),
            "token_id": str(self.token_id),
            "name": decrypt(self.name), 
            "user_id": str(self.user_id),  
            "description": decrypt(self.description)  
        }
