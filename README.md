## Crypt
Crypt is a simple locally run secrets manager with no designated frontend. The purpose of this is to provide a secure and simple way to store and access secrets with simple RBAC baked in.


## Getting Started
do this to use this jawn


## Features
### API Functionality
#### User
- Delete your own account
- Update your username
- Health check
- Delete all your secrets
- Get all your secrets
- Delete specific secrets
- Create new secrets
- Retrieve new secrets
- Update existing secrets
- Delete your access token
- Regenerate your access token
#### Admin
- Get all users
- Delete a user
- Create a new user
- Create admin user
- Get a specific user
- Health check
- Delete all secrets by username
- Delete secret by ID
- Delete user token
- Create a user token
- Regenerate tokens
### RBAC
- User
  - Simple user who has access to all secret functionality. 
- Admin
  - A singular admin user whose token has the ability to manage all users and secrets as well as the basic functionality.
### RSA Encryption
The fields that are and are not encrypted can be seen here in this code snippet. Lines are have the # Encrypted comment are RSA encrypted in the database.

The following is the contents of the model.py file that defines the pydantic models of how different objects are stored in their respective tables.

All information that COULD be considered PII is encrypted and thus secure. In the event of a database leak, all secret information is protected so long as the private key itself is not lost.

Since these objects are stored in different tokens, they are linked primarily by `user_id`. Note that an entry in each table requires this field. This means that all Tokens and Secrets must be tied to a User via this field.

```python
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

```
### Postgres Database
As seen in the previous section, there are 3 tables which faciliate all of the object storage on the backend.

1.  users
All User objects have a username and a user_id. On a call to `POST api/v1/user/{username}`, a random UUID is generated for the new user, the username is encrypted, and together they make up a singular User object. In addition to this, an access token will also be generated for the User.

2.  tokens
Tokens are initially created when its corresponding user is created. They follow similar suite, where the token id is a random UUID, the `user_id` is tied to the previoulsy created User, and the token itself is a string containing lowercase letters, uppercase letters, and numbers, and is stored encrypted as well.

3.  secrets
Tokens are tied to both the user via the `user_id` and the token that created it via the `token_id`. In addition, it contains the value of the secret, the name of the secret, and a description of the secret, all of which are stored encrypted. When users call `GET /api/v1/secrets`, it will return all of their secrets with their names and descriptions decrypted.
### Swagger UI 
As a result of using FastAPI as the API provider, a swagger UI is automatically generated for the project. This page is available at `http://localhost:8000/docs` and groups all of the API routes by User and Admin access. This is effectively the frontend, as this project is minimalistic.

## Technologies used
- ### Python
- ### FastAPI
- ### Postgres
- ### Docker
