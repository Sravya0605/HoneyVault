from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

class MongoDB:
    def __init__(self):
        self.client: AsyncIOMotorClient | None = None
        self.db = None

    async def connect(self):
        """Establishes an asynchronous connection to the MongoDB server."""
        print("Connecting to MongoDB...")
        self.client = AsyncIOMotorClient(settings.MONGO_URI)
        self.db = self.client[settings.DB_NAME]
        print("MongoDB connection established.")

    async def close(self):
        """Closes the MongoDB connection."""
        if self.client:
            self.client.close()
            print("MongoDB connection closed.")

    def get_database(self):
        """
        Returns the database instance.

        Raises:
            Exception: If the database is not initialized.
        """
        if self.db is None:
            raise Exception("Database not initialized. Call connect() first.")
        return self.db

# Singleton instance
mongo = MongoDB()