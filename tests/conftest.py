import pytest
import asyncio
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from app.main import app
from app.db.mongo import mongo
from app.core.config import settings

# Set up a separate test database
TEST_MONGO_URI = f"{settings.MONGO_URI}_test"
TEST_DB_NAME = f"{settings.DB_NAME}_test"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_db_client():
    """Fixture to create a test database client."""
    client = AsyncIOMotorClient(TEST_MONGO_URI)
    yield client
    client.close()

@pytest.fixture(scope="function", autouse=True)
async def db(test_db_client):
    """
    Fixture that provides a test database instance and handles cleanup.
    This fixture is auto-used for every test function.
    """
    db_instance = test_db_client[TEST_DB_NAME]
    
    # Override the app's database getter
    def override_get_database():
        return db_instance
        
    mongo.get_database = override_get_database

    # Yield the database instance for tests to use if needed
    yield db_instance

    # Teardown: drop all collections in the test database after each test
    collection_names = await db_instance.list_collection_names()
    for name in collection_names:
        await db_instance[name].drop()

@pytest.fixture(scope="function")
async def client(db) -> AsyncClient:
    """
    Fixture to create a test client for the FastAPI app.
    """
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
