from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from routes.v1.users import find_user_by_username
from sqlalchemy.orm import Session
from database import get_db
from models.models import Secret, Token, User
from routes.v1.shared_methods import check_auth, check_auth_admin, generate_token, generate_uuid, encrypt, decrypt, load_private_key, load_public_key, get_decrypted, get_encrypted
from routes.v1.tokens import find_token_by_value

router = APIRouter()

class SecretRequest(BaseModel):
    """Model to validate the secret input in requests."""
    secret: str = Field(..., description="The secret value to be stored.")
    description: str = Field(..., description="An optional description for the secret.")

class SecretUpdateRequest(BaseModel):
    """Model to validate the secret update input."""
    secret: Optional[str] = Field(None, description="The new secret value.")
    description: Optional[str] = Field(None, description="The new description for the secret.")

def find_secret_by_name_id(db, name, token_id) -> Secret:
    secrets: List[Secret] = db.query(Secret).filter(Secret.token_id == token_id)
    for secret in secrets:
        current_secret = get_decrypted(secret.name)
        if current_secret == name:
            return secret
    return None

def get_secrets_by_token(value: str, db: Session) -> List[Secret]:
    """Retrieve secrets associated with a given token.
    
    Args:
        token (str): The token value to look up.
        db (Session): The database session object.
    
    Returns:
        List[Secret]: List of Secret objects associated with the token.
    
    Raises:
        HTTPException: If the token is not found.
    """
    
    # Check if the encrypted token  exists in the database
    token: Token = find_token_by_value(db, f"Bearer {value}")     
    print(f"Token: {token.to_dict()}")
    if not token:
        raise HTTPException(status_code=404, detail="Could not find the provided token.")

    secrets = db.query(Secret).filter(Secret.token_id == token.id).all()
    return secrets

@router.delete("/api/v1/secrets/{user_id}", tags=["Admin Access"], summary="Delete all secrets by username",
               description="Delete all secrets associated with the provided username. Requires the user to be authenticated via a Bearer token. Deletes all secrets for the user identified by the username. If successful, a confirmation message is returned. If there is an error, an appropriate error response is returned.")
def delete_user_secrets_by_user_id(user_id: str, db: Session = Depends(get_db), 
                                    authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete all secrets associated with the given username.

    Args:
        username (str): The username whose secrets are to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A confirmation message indicating that all secrets were deleted.

    Raises:
        HTTPException: 
            - 401: If the token is not valid or the user does not exist.
            - 404: If no user with the provided username is found.
            - 500: If there is an internal error during the deletion process.
    """
    check_auth_admin(authorization, f"DELETE /api/v1/secrets/{user_id}")
    
    try:
        # Extract token value from the authorization header
        token: Token = db.query(Token).filter(Token.user_id == user_id)

        if not token:
            raise HTTPException(status_code=401, detail="Invalid or expired token.")

        # Retrieve the user associated with the token
        user: User = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User with the provided username not found.")
        
        # Fetch and delete all secrets associated with the user
        secrets = db.query(Secret).filter(Secret.user_id == user_id).all()
        size = len(secrets)
        for secret in secrets:
            db.delete(secret)

        db.commit()

        return {"message": f"All ({size}) secrets for username '{get_decrypted(user.username)}' have been successfully deleted."}

    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail=f"Internal error deleting secrets: {e}")

@router.delete("/api/v1/secrets", tags=["Member Access"], summary="Delete all secrets by username",
               description="Delete all secrets associated with the provided username. Requires the user to be authenticated via a Bearer token. Deletes all secrets for the user identified by the username. If successful, a confirmation message is returned. If there is an error, an appropriate error response is returned.")
def delete_user_secrets(db: Session = Depends(get_db), 
                                    authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete all secrets associated with the given username.

    Args:
        username (str): The username whose secrets are to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A confirmation message indicating that all secrets were deleted.

    Raises:
        HTTPException: 
            - 401: If the token is not valid or the user does not exist.
            - 404: If no user with the provided username is found.
            - 500: If there is an internal error during the deletion process.
    """
    check_auth(authorization, db, "/api/v1/secrets/{username}")
    
    try:
        # Extract token value from the authorization header
        token_value = authorization.split(' ')[1]
        token = find_token_by_value(db, f"Bearer {token_value}")

        if not token:
            raise HTTPException(status_code=401, detail="Invalid or expired token.")

        # Retrieve the user associated with the token
        user: User = db.query(User).filter(User.id == token.id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User with the provided username not found.")
        
        # Fetch and delete all secrets associated with the user
        secrets = db.query(Secret).filter(Secret.user_id == user.id).all()
        for secret in secrets:
            db.delete(secret)

        db.commit()

        return {"message": f"All secrets for username '{get_decrypted(user.username)}' have been successfully deleted."}

    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail=f"Internal error deleting secrets: {e}")

@router.delete("/api/v1/admin/secret/{secret_id}", tags=["Admin Access"], summary="Admin delete secret by ID",
               description="Delete a specific secret by its ID. This endpoint requires admin access. The secret is identified by its ID and is removed from the database. If the secret is not found or an error occurs, appropriate error responses are returned.")
def admin_delete_secret(secret_id: UUID, db: Session = Depends(get_db),
                        authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """Admin delete a specific secret by its ID.

    Args:
        secret_id (UUID): The ID of the secret to be deleted.
        db (Session): The database session object.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: Confirmation message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If the secret with the specified ID is not found.
            - 401: If the user is not authorized as an admin.
            - 500: If there is an internal error during the deletion process.
    """
    # Check if the requester has admin rights
    check_auth_admin(authorization, f"/api/v1/admin/secret/{secret_id}")

    try:
        # Retrieve the secret object from the database
        secret: Secret = db.query(Secret).filter(Secret.id == secret_id).first()
        if not secret:
            raise HTTPException(status_code=404, detail=f"Secret with ID '{secret_id}' not found.")

        # Delete the secret from the database
        db.delete(secret)
        db.commit()

        return {
            "message": f"Secret with ID '{secret_id}' successfully deleted."
        }

    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail=f"Error deleting secret: {e}")

@router.delete("/api/v1/secret/{name}", tags=["Member Access"], summary="Delete a specific secret",
               description="Delete a specific secret by its name. The request requires the user to be authenticated via a Bearer token. If the secret is found, it will be deleted from the database. If the secret is not found or if there's an error during deletion, appropriate error responses are returned.")
def delete_secret(name: str, db: Session = Depends(get_db),
                   authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """Delete a specific secret by its name.

    Args:
        name (str): The name of the secret to be deleted.
        db (Session): The database session object.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: Confirmation message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If the secret with the specified name is not found.
            - 500: If there is an internal error during the deletion process.
    """
    check_auth(authorization, db, f"DELETE /api/v1/secret/{name}")

    try:
        # Retrieve the token object from the database
        token: Token = find_token_by_value(db, authorization)
        if not token:
            raise HTTPException(status_code=404, detail="Could not find the provided token.")

        # Retrieve the secret object from the database
        secret: Secret = find_secret_by_name_id(db, name, token.id)
        if not secret:
            raise HTTPException(status_code=404, detail=f"Secret with name '{name}' not found.")
        print(f"Secret: {secret}")
        # Delete the secret from the database
        db.delete(secret)
        db.commit()

        return {
            "message": f"Secret with name '{name}' successfully deleted."
        }

    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail=f"Error deleting secret: {e}")

@router.post("/api/v1/secret/{name}", tags=["Member Access"], summary="Upload a new secret",
             description="Upload a new secret for a user. The request requires the user to be authenticated via a Bearer token. The secret is encrypted before being stored in the database. The endpoint also accepts an optional description for the secret. Upon successful storage, a confirmation message is returned. If the user cannot be found or if there's an error during storage, appropriate error responses are returned.")
def upload_secret(name: str, request: SecretRequest, db: Session = Depends(get_db), 
                    authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """Upload a new secret for a user.
    
    Args:
        name (str): The name associated with the secret.
        request (SecretRequest): The secret request body containing the secret and an optional description.
        db (Session): The database session object.
        authorization (str): The Authorization header containing the Bearer token.
    
    Returns:
        dict: Confirmation message with the name of the secret.
    
    Raises:
        HTTPException: If the user is not found or there is an error storing the secret.
    """
    check_auth(authorization, db, f"POST /api/v1/secret/{name}")
    token: Token = find_token_by_value(db, authorization)
    user: User = db.query(User).filter(User.id == token.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Could not find any user associated with the provided token.")
    
    try:
        # Find a duplicate secret
        secrets: List[Secret] = db.query(Secret).filter(Secret.user_id == user.id)
        for secret in secrets:
            if get_decrypted(secret.name) == name:
                raise HTTPException(status_code=401, detail=f"You already have a secret with the name: {name}.")

        # Create a new Secret object
        secret_entry = Secret(
            id=generate_uuid(),
            value=get_encrypted(request.secret),
            token_id=token.id,
            name=get_encrypted(name),
            user_id=token.user_id,
            description=get_encrypted(request.description)
        )

        db.add(secret_entry)
        db.commit()

        return {
            "name": get_decrypted(secret_entry.name),
            "description": get_decrypted(secret_entry.description),
            "value": get_decrypted(secret_entry.value)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error storing secret: {e}")

@router.get("/api/v1/secret/{name}", tags=["Member Access"], summary="Retrieve a specific secret",
            description="Retrieve and decrypt a specific secret by its name. The request requires the user to be authenticated via a Bearer token. If the secret is found, it is decrypted and returned along with its name. If the secret is not found or if there's an error during decryption, appropriate error responses are returned.")
def get_secret(name: str, db: Session = Depends(get_db),  
              authorization: str = Header(..., alias="X-Auth-Token")):
    """Retrieve and decrypt a specific secret.
    
    Args:
        name (str): The name of the secret to retrieve.
        db (Session): The database session object.
        authorization (str): The Authorization header containing the Bearer token.
    
    Returns:
        dict: The decrypted secret associated with the name.
    
    Raises:
        HTTPException: If the secret is not found or there is an error decrypting it.
    """
    check_auth(authorization, db, "/api/v1/secret/{name}")
    try:
        token_value = authorization.split(' ')[1]
        secrets = get_secrets_by_token(token_value, db)
        target_secret = None
        for secret in secrets:
            if get_decrypted(secret.name) == name:
                target_secret = secret
        if target_secret:
            try:
                return {"name": get_decrypted(target_secret.name), "value": get_decrypted(target_secret.value)}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error decrypting secret: {e}")
            
        else:
            raise HTTPException(status_code=404, detail=f"Secret with provided name '{name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/secrets", tags=["Member Access"], summary="Retrieve all secrets",
            description="Retrieve a list of all secrets associated with the provided token. The request requires the user to be authenticated via a Bearer token. The response includes a list of secret names and their descriptions. If there's an error retrieving the secrets, an appropriate error response is returned.")
def get_secrets(db: Session = Depends(get_db),  
              authorization: str = Header(..., alias="X-Auth-Token")):
    """Retrieve a list of all secrets associated with the provided token.
    
    Args:
        db (Session): The database session object.
        authorization (str): The Authorization header containing the Bearer token.
    
    Returns:
        List[dict]: A list of dictionaries, each containing the name and description of a secret.
    
    Raises:
        HTTPException: If there is an error retrieving the secrets.
    """
    check_auth(authorization, db, "/api/v1/secrets")
    try:
        token_value = authorization.split(' ')[1]
        secrets: List[Secret] = get_secrets_by_token(token_value, db)
        # Generate response list with secret names and descriptions
        response = [{"name": get_decrypted(secret.name), "description": get_decrypted(secret.description)} for secret in secrets]
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving secrets: {e}")

@router.patch("/api/v1/secret/{name}", tags=["Member Access"], summary="Update an existing secret",
              description="Update an existing secret's value and/or description. The request requires the user to be authenticated via a Bearer token. The secret value can be updated if provided, and/or the description can be updated. If the secret is found and successfully updated, the updated secret information is returned. If there is an error during the update process, an appropriate error response is returned.")
def update_secret(name: str, update_request: SecretUpdateRequest, db: Session = Depends(get_db), 
                     authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Update an existing secret's value and/or description.

    Args:
        name (str): The name of the secret to be updated.
        update_request (SecretUpdateRequest): The new values for secret and/or description.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A dictionary containing the updated secret information.

    Raises:
        HTTPException: 
            - 404: If the secret with the specified name is not found.
            - 500: If there is an internal error during the update.
    """
    check_auth(authorization, db, f"PATCH /api/v1/secret/{name}")
    
    try:
        # Retrieve the token object from the database
        token: Token = find_token_by_value(db, authorization)
        if not token:
            raise HTTPException(status_code=404, detail="Could not find the provided token.")

        # Retrieve the secret object from the database
        secret: Secret = find_secret_by_name_id(db, name, token.id)
        if not secret:
            raise HTTPException(status_code=404, detail=f"Secret with name '{name}' not found.")
        
        # Update the secret and/or description if provided
        if update_request.secret is not None:
            secret.value = get_encrypted(update_request.secret)
        
        if update_request.description is not None:
            secret.description = get_encrypted(update_request.description)

        # Commit the changes to the database
        db.commit()

        return {
            "name": secret.name,
            "description": secret.description if update_request.description else "Not updated",
            "value": "Updated" if update_request.secret else "Not Updated"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating secret: {e}")
