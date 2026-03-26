import pytest
import pytest_asyncio
from httpx import AsyncClient
from httpx import ASGITransport
from motor.motor_asyncio import AsyncIOMotorClient

from app.main import app
from app.db.mongo import mongo
from app.core.config import settings

# Set up a separate test database while reusing a valid Mongo URI.
TEST_MONGO_URI = settings.MONGO_URI
TEST_DB_NAME = f"{settings.DB_NAME}_test"

@pytest_asyncio.fixture(scope="function")
async def test_db_client():
    """Fixture to create a test database client."""
    client = AsyncIOMotorClient(TEST_MONGO_URI)
    yield client
    client.close()

@pytest_asyncio.fixture(scope="function", autouse=True)
async def db(test_db_client):
    """
    Fixture that provides a test database instance and handles cleanup.
    This fixture is auto-used for every test function.
    """
    db_instance = test_db_client[TEST_DB_NAME]
    
    # Override the app's database getter
    def override_get_database():
        return db_instance

    previous_db = mongo.db
    mongo.get_database = override_get_database
    mongo.db = db_instance

    # Yield the database instance for tests to use if needed
    yield db_instance

    mongo.db = previous_db

    # Teardown: drop all collections in the test database after each test
    collection_names = await db_instance.list_collection_names()
    for name in collection_names:
        await db_instance[name].drop()

@pytest_asyncio.fixture(scope="function")
async def client(db) -> AsyncClient:
    """
    Fixture to create a test client for the FastAPI app.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
