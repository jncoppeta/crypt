from typing import List
from uuid import UUID
import uuid
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import get_db
from models.models import Secret, Token, User
from routes.v1.shared_methods import check_auth, check_auth_admin, generate_token, generate_uuid, is_admin_token, get_decrypted, get_encrypted

router = APIRouter()

def find_token_by_value(db, authorization) -> Token:
    print(f"Authorization: {authorization}" )
    tokens: List[Token] = db.query(Token).all()
    for token in tokens:
        if get_decrypted(token.value) == authorization.split(' ')[1]:
            return token
    return None

@router.delete("/api/v1/token", tags=["Member Access"], summary="Delete a user token by its associtaed bearer token.",
               description="Delete a user token. Upon successful deletion, a confirmation message is returned. If no token is found for the provided user ID, a 404 error is returned. In case of internal errors during the process, a 500 error is raised.")
def delete_token_self(db: Session = Depends(get_db),
                authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete a user token by their user ID.

    Args:
        user_id (str): The ID of the user whose token is to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If no token with the specified user_id is found.
            - 500: If there is an internal error during the deletion process.
    """
    # Check if the requester has admin rights
    check_auth(authorization, db, f"DELETE /api/v1/tokens")
    
    # Retrieve the token from the database based on the authorization token
    target_token = find_token_by_value(db, authorization)
    if not target_token:
        raise HTTPException(status_code=404, detail=f"No token found.")
    
    try:
        # Delete the token from the database
        db.delete(target_token)
        db.commit()
        return {"message": f"Token with user_id {target_token.user_id} successfully deleted."}
    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail="Internal error deleting the token.")

@router.delete("/api/v1/token/{user_id}", tags=["Admin Access"], summary="Delete a user token",
               description="Delete a user token by specifying the user ID. This endpoint requires admin privileges to ensure only authorized users can delete tokens. Upon successful deletion, a confirmation message is returned. If no token is found for the provided user ID, a 404 error is returned. In case of internal errors during the process, a 500 error is raised.")
def delete_token(user_id: str, db: Session = Depends(get_db),
                authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete a user token by their user ID.

    Args:
        user_id (str): The ID of the user whose token is to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If no token with the specified user_id is found.
            - 500: If there is an internal error during the deletion process.
    """
    # Check if the requester has admin rights
    check_auth_admin(authorization, f"/api/v1/tokens/{user_id}")
    
    # Retrieve the token from the database based on the user_id
    token = db.query(Token).filter(Token.user_id == user_id).first()
    
    if not token:
        raise HTTPException(status_code=404, detail=f"No token found with user_id: {user_id}.")
    
    try:
        # Delete the token from the database
        db.delete(token)
        db.commit()
        return {"message": f"Token with user_id {user_id} successfully deleted."}
    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail="Internal error deleting the token.")

@router.post("/api/v1/token/{user_id}", tags=["Admin Access"], summary="Create a token for a user",
             description="Create a new token for the specified user ID. This endpoint requires admin privileges to ensure that only authorized users can create tokens. It first checks if the user exists and does not already have a token. If the user does not exist or already has a token, appropriate error responses are provided. A unique token is generated and assigned to the user, and the new token is returned upon successful creation.")
def create_token(user_id: str, db: Session = Depends(get_db), 
              authorization: str = Header(..., alias="X-Auth-Token")):
    """
    Create a new token for the given user ID.

    Args:
        user_id (str): The ID of the user for whom the token is being created.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A dictionary containing the success message and the created token object.

    Raises:
        HTTPException: If an error occurs during token creation or authorization.
    """
    try:
        check_auth_admin(authorization, f"POST /api/v1/token{user_id}")
        # 1. Check user exists and doesn't have a token
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User does not exist.")
        user_token = db.query(Token).filter(Token.user_id == user_id).first()
        if user_token:
            raise HTTPException(status_code=401, detail="User already has a token.")
        
        # 2. Generate unique ID for token
        token_id = ""
        while True:
            token_id = generate_uuid()
            search = db.query(Token).filter(Token.id == token_id).first()
            if not search:
                break

        # 3. Generate token itself
        token_value = ""
        encrypted_value = ""
        while True:
            token_value = generate_token()
            encrypted_value = get_encrypted(token_value)
            search = db.query(Token).filter(Token.value == encrypted_value).first()
            if not search:
                break
        
        new_token = Token(
            id=token_id,
            value=encrypted_value,
            user_id=user_id
        )

        # Add the new token to the session and commit
        db.add(new_token)
        db.commit()

        return {"token": token_value}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/api/v1/token", tags=["Member Access"], summary="Regenerate your token.",
              description="Regenerate a new token. This operation generates a new token for the user and updates all associated secrets with the new token ID. If the user does not exist or does not have an existing token, appropriate error responses are provided. The new token is returned upon successful regeneration.")
def regenerate_token(db: Session = Depends(get_db), 
                      authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Regenerate a new token for the user and update all associated secrets.

    Args:
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A dictionary containing the success message and the regenerated token.

    Raises:
        HTTPException: 
            - 401: If the user does not exist or does not have an existing token.
            - 500: If there is an internal error during the token regeneration.
    """
    check_auth(authorization, db, "/api/v1/token")

    try:
        # 1. Retrieve the current token and associated user
        old_token = find_token_by_value(db, authorization)
        if not old_token:
            raise HTTPException(status_code=401, detail="Existing token not found.")
        
        user: User = db.query(User).filter(User.id == old_token.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User does not exist.")

        # 2. Generate a new unique token ID
        new_token_id = generate_uuid()
        while db.query(Token).filter(Token.id == new_token_id).first():
            new_token_id = generate_uuid()
        
        # 3. Generate a new unique token value
        new_token_value = generate_token()
        encrypted_new_token_value = get_encrypted(new_token_value)
        while db.query(Token).filter(Token.value == encrypted_new_token_value).first():
            new_token_value = generate_token()
            encrypted_new_token_value = get_encrypted(new_token_value)
        
        # 4. Retrieve and update all associated secrets
        secrets: List[Secret] = db.query(Secret).filter(Secret.token_id == old_token.id).all()
        for secret in secrets:
            secret.token_id = new_token_id
            print(f"Updated Secret: {secret.to_dict()}")
        
        # 5. Update the existing token with new values
        old_token.id = new_token_id
        old_token.value = encrypted_new_token_value
        
        db.commit()

        return {"token": new_token_value}

    except Exception as e:
        db.rollback()  # Rollback in case of an error during the process
        raise HTTPException(status_code=500, detail=f"Error regenerating token: {e}")

    
@router.patch("/api/v1/token/{user_id}", tags=["Admin Access"], summary="Regenerate a token for a user",
              description="Regenerate a new token for the specified user ID. This endpoint requires admin privileges to ensure that only authorized users can regenerate tokens. It first checks if the user exists and has an existing token. If the user does not exist or does not have an existing token, appropriate error responses are provided. A unique token is generated and assigned to the user, and the new token is returned upon successful regeneration.")
def regenerate_token(user_id: str, db: Session = Depends(get_db), 
                      authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Regenerate a new token for the given user ID.

    Args:
        user_id (str): The ID of the user for whom the token is being regenerated.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A dictionary containing the success message and the regenerated token.

    Raises:
        HTTPException: 
            - 401: If the user does not exist or does not have an existing token.
            - 500: If there is an internal error during the token regeneration.
    """
   
    check_auth_admin(authorization, f"PATCH /api/v1/token/{user_id}")

    try:
        user: User = db.query(User).filter(User.id == user_id).first()
        token: Token = db.query(Token).filter(Token.user_id == user_id).first()

        if not user:
            raise HTTPException(status_code=401, detail="User does not exist.")
        if not token:
            raise HTTPException(status_code=401, detail="User does not have an existing token.")

        # 2. Generate unique ID for new token
        new_token_id = ""
        while True:
            new_token_id = generate_uuid()
            search = db.query(Token).filter(Token.id == new_token_id).first()
            if not search:
                break
        
        # 3. Generate new token value
        new_token_value = ""
        encrypted_value = ""
        while True:
            new_token_value = generate_token()
            encrypted_value = get_encrypted(new_token_value)
            search = db.query(Token).filter(Token.value == encrypted_value).first()
            if not search:
                break

        secrets: List[Secret] = db.query(Secret).filter(Secret.token_id == token.id).all()
        for secret in secrets:
            secret.token_id = new_token_id
            print(f"Updated Secret: {secret.to_dict()}")
        # Update the existing token with new values
        token.id = new_token_id
        token.value = encrypted_value

        db.commit()

        return {"token": new_token_value}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal error regenerating the token: {e}")