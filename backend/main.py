from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from database import SessionLocal, engine, Base, get_db
from routes.v1.users import router as users_router
from routes.v1.secrets import router as secrets_router
from routes.v1.tokens import router as tokens_router

app = FastAPI()

# Include the routes from the routes module
app.include_router(users_router)
app.include_router(secrets_router)
app.include_router(tokens_router)

# Create the database tables if they do not exist
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
