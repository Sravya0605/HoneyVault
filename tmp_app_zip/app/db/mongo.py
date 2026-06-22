from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

class MongoDB:
    def __init__(self):
        self.client: AsyncIOMotorClient | None = None
        self.db: AsyncIOMotorDatabase | None = None

    async def connect(self):
        """Establish MongoDB connection."""
        try:
            logger.info("Connecting to MongoDB...")
            self.client = AsyncIOMotorClient(settings.MONGO_URI)

            # Force connection
            await self.client.admin.command("ping")

            self.db = self.client[settings.DB_NAME]
            logger.info("MongoDB connection established.")

        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise e

    async def close(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed.")

    def get_database(self) -> AsyncIOMotorDatabase:
        if self.db is None:
            raise Exception("MongoDB not connected. Did startup_event run?")
        return self.db


# Singleton instance
mongo = MongoDB()