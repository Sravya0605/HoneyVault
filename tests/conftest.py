import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from motor.motor_asyncio import AsyncIOMotorClient

from app.main import app
from app.db.mongo import mongo
from app.core.config import settings

# Set up a separate test database
TEST_MONGO_URI = settings.MONGO_URI
TEST_DB_NAME = f"{settings.DB_NAME}_test"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def db():
    """
    Fixture that provides a test database instance and handles cleanup.
    This fixture is auto-used for every test function.
    """
    client = AsyncIOMotorClient(TEST_MONGO_URI)
    db_instance = client[TEST_DB_NAME]
    
    # Override the app's database getter
    def override_get_database():
        return db_instance
        
    mongo.get_database = override_get_database

    yield db_instance

    # Teardown: drop all collections in the test database after each test
    collection_names = await db_instance.list_collection_names()
    for name in collection_names:
        await db_instance[name].drop()
    client.close()

@pytest.fixture(scope="function")
async def client(db) -> AsyncClient:
    """
    Fixture to create a test client for the FastAPI app.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
