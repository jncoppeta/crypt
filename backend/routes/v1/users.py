from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from database import get_db
from models.models import Token, User
from routes.v1.shared_methods import check_auth, check_auth_admin, generate_uuid, get_decrypted, get_encrypted
from routes.v1.tokens import create_token, delete_token, delete_token_self
from routes.v1.shared_methods import encrypt, decrypt, load_private_key, load_public_key
from dotenv import load_dotenv
import os

router = APIRouter()

class UsernameUpdateRequest(BaseModel):
    """Model to validate the username update request body."""
    new_username: str = Field(..., description="The new username to update to.")

def find_user_by_username(db, username) -> User:
    users: List[User] = db.query(User).all()
    for user in users:
        current_user_username = get_decrypted(user.username)
        if current_user_username == username:
            return user
    return None

@router.delete("/api/v1/users", tags=["Member Access"], summary="Delete a user by its assoicated bearer token.",
               description="Delete a user from the database by their username. The operation also deletes any associated tokens. If successful, a confirmation message is returned. If the user is not found or an internal error occurs, appropriate error responses are returned.")
def delete_user_self(db: Session = Depends(get_db),
                authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete a user by their username.

    Args:
        username (str): The username of the user to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If no user with the specified username is found.
            - 500: If there is an internal error during the deletion process.
    """
    # Check if the requester has admin rights
    check_auth(authorization, db, f"DELETE /api/v1/users")
    
    # Retrieve the user from the database based on the username
    token: Token = db.query(Token).filter(Token.value == authorization.split(' ')[1]).first()
    user: User = db.query(User).filter(User.id == token.user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail=f"No user found with username: {user.username}.")
    
    try:
        # Delete the user from the database
        db.delete(user)
        db.commit()
        removed_token = delete_token_self(user.id, db, authorization)

        return {
            "User Deletion:": f"User with username {user.username} successfully deleted.",
            "Token Deletion": removed_token['message'] 
        }
    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail="Internal error deleting the user.")

@router.delete("/api/v1/users/{username}", tags=["Admin Access"], summary="Delete a user by username",
               description="Delete a user from the database by their username. Requires admin privileges. The operation also deletes any associated tokens. If successful, a confirmation message is returned. If the user is not found or an internal error occurs, appropriate error responses are returned.")
def delete_user(username: str, db: Session = Depends(get_db),
                authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Delete a user by their username.

    Args:
        username (str): The username of the user to be deleted.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A message indicating the result of the deletion operation.

    Raises:
        HTTPException: 
            - 404: If no user with the specified username is found.
            - 500: If there is an internal error during the deletion process.
    """
    from routes.v1.secrets import delete_user_secrets_by_user_id
    # Check if the requester has admin rights
    check_auth_admin(authorization, f"DELETE /api/v1/users/{username}")
    # Retrieve the user from the database based on the username
    users: List[User] = db.query(User).all()
    target_user = None
    for user in users:
        if decrypt(user.username, load_private_key()) == username:
            target_user = user
    if not target_user:
        raise HTTPException(status_code=404, detail=f"No user found with username: {username}.")
    
    try:
        # Delete the user from the database
        deleted_secrets = delete_user_secrets_by_user_id(user.id, db, authorization)
        print(deleted_secrets)
        db.delete(target_user)
        db.commit()
        removed_token = delete_token(user.id, db, authorization)
        print(removed_token)
        
        return {
            "User Deletion:": f"User with username {username} successfully deleted.",
            "Token Deletion": removed_token['message'],
            "Secrets Deletion": deleted_secrets['message']
        }
    except Exception as e:
        db.rollback()  # Rollback in case of an error during the delete operation
        raise HTTPException(status_code=500, detail=f"Internal error deleting the user: {e}")


@router.post("/api/v1/users/admin", tags=["Admin Access"])
def create_admin_user(db: Session = Depends(get_db)):
    INIT_TOKEN = os.getenv("INIT_TOKEN")
    print(f"Init: {INIT_TOKEN}")
    return create_user("admin", db, f"Bearer {INIT_TOKEN}")

@router.post("/api/v1/users/{username}", tags=["Admin Access"], summary="Create a new user",
             description="Create a new user with the specified username. Requires admin privileges. The new user is assigned a unique UUID and an authentication token. If the username already exists, an error response is returned. On success, the details of the created user and their token are returned.")
def create_user(username: str, db: Session = Depends(get_db), 
                authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Create a new user with the specified username.

    Args:
        username (str): The username of the user to be created.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A message saying success

    Raises:
        HTTPException: 
            - 401: If the username is already taken.
            - 500: If there is an internal error during user creation.
    """
    print(f"Init from create user: {authorization}")
    check_auth_admin(authorization, f"/api/v1/users/{username}")
    encrypted_username = get_encrypted(username)
    # Check if the username already exists
    existing_user = find_user_by_username(db, username)
    if existing_user:
        raise HTTPException(status_code=401, detail=f"The username {username} is already taken.")
    
    # Generate a unique UUID for the new user
    user_uuid = ""
    while True:
        user_uuid = generate_uuid()
        search = db.query(User).filter(User.id == user_uuid).first()
        if not search:
            break
    
    # Create a new user and add it to the database
    new_user = User(
        id=user_uuid,
        username=encrypted_username
    )

    try:
        db.add(new_user)
        db.commit()
        new_token: dict = create_token(user_uuid, db, authorization)
        token_object: Token = db.query(Token).filter(Token.user_id == new_user.id).first()
        if authorization.split(' ')[1] == os.getenv("INIT_TOKEN"):
            with open('routes/admin_token.txt', 'w') as f:
                f.write(token_object.value)

            print(f"Updated ADMIN_TOKEN environment variable.")
        return {
            "username": username,
            "token": new_token['token']
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal error creating new user: {e}")

@router.get("/api/v1/users", tags=["Admin Access"], summary="Retrieve all users",
            description="Retrieve a list of all users in the database. Requires admninistrator authentication via a Bearer token. Returns a list of usernames. If there is an error during retrieval, an appropriate error response is returned.")
def get_users(db: Session = Depends(get_db), 
              authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Retrieve a list of all users.

    Args:
        db (Session): The database session to use for querying.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A list of users.

    Raises:
        HTTPException: 
            - 500: If there is an error retrieving the user list.
    """
    check_auth_admin(authorization, "GET /api/v1/users")
    
    try:
        users: List[User] = db.query(User).all()
        return {"users": [user.to_dict() for user in users]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/users/{id}", tags=["Admin Access"], summary="Retrieve a specific user by ID",
            description="Retrieve a specific user by their unique ID. Requires authentication via a Bearer token. If the user with the specified ID is found, their details are returned. If not, or if an internal error occurs, appropriate error responses are returned.")
def get_user(id: UUID, db: Session = Depends(get_db), 
             authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Retrieve a specific user by their ID.

    Args:
        id (UUID): The unique identifier of the user to retrieve.
        db (Session): The database session to use for querying.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: The user with the specified ID.

    Raises:
        HTTPException: 
            - 404: If the user with the specified ID is not found.
            - 500: If there is an error retrieving the user.
    """
    check_auth_admin(authorization, f"/api/v1/users/{id}")
    
    try:
        user: User = db.query(User).filter(User.id == id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return {"user": user.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/health", tags=["Member Access", "Admin Access"], summary="Check API health",
            description="Check the health of the API. This endpoint is used to verify that the service is up and running. Returns a simple message indicating that the service is healthy.")
def health() -> dict:
    """
    Check the health of the API.

    Returns:
        dict: A dictionary indicating that the service is healthy.
    """
    return {"message": "Healthy"}

@router.patch("/api/v1/users", tags=["Member Access"], summary="Update the username of the current user",
              description="Update the username for the current user. Requires authentication via a Bearer token. The current username is fetched from the token, and the new username is provided in the request body. If successful, returns the old and new usernames. If the new username is already taken or an internal error occurs, appropriate error responses are returned.")
def update_username(update_request: UsernameUpdateRequest, db: Session = Depends(get_db), 
                     authorization: str = Header(..., alias="X-Auth-Token")) -> dict:
    """
    Update the username for a specific user.

    Args:
        current_username (str): The current username of the user whose username is to be updated.
        update_request (UsernameUpdateRequest): The new username to be set.
        db (Session): The database session to use for querying and committing.
        authorization (str): The Authorization header containing the Bearer token.

    Returns:
        dict: A dictionary with the updated username information.

    Raises:
        HTTPException: 
            - 404: If the user with the specified current username is not found.
            - 401: If the authorization fails or the new username is already taken.
            - 500: If there is an internal error during the update.
    """
    check_auth(authorization, db, f"PATCH /api/v1/users")
    
    try:
        # Retrieve the user from the database based on the current username
        token: Token = db.query(Token).filter(Token.value == authorization.split(' ')[1]).first()
        user: User = db.query(User).filter(User.id == token.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        current_username = user.username
        # Check if the new username already exists
        existing_user = find_user_by_username(db, current_username)
        if existing_user:
            raise HTTPException(status_code=401, detail="The new username is already taken.")
        
        # Update the user's username
        user.username = update_request.new_username
        db.commit()
        
        return {"old_username": current_username, "new_username": update_request.new_username}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating username: {e}")