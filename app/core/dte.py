import random
import string
from app.core.config import settings

class CloudSecretDTE:
    """
    Lightweight DTE-style sampler for cloud credential decoys.

    It maps uniform randomness (seed) into outputs drawn from a modeled
    distribution over realistic cloud-secret context.
    """

    def __init__(self):
        self.prefix = settings.KEY_PREFIX
        self.length = settings.KEY_LENGTH
        self._services = [
            ("s3", 0.30),
            ("ec2", 0.25),
            ("iam", 0.15),
            ("rds", 0.10),
            ("lambda", 0.10),
            ("cloudtrail", 0.10),
        ]
        self._regions = [
            ("us-east-1", 0.35),
            ("us-west-2", 0.20),
            ("eu-west-1", 0.15),
            ("ap-southeast-1", 0.15),
            ("sa-east-1", 0.15),
        ]

    def _random_body(self, rng: random.Random, length: int) -> str:
        chars = string.ascii_uppercase + string.digits
        return "".join(rng.choices(chars, k=length))

    def _weighted_pick(self, rng: random.Random, table: list[tuple[str, float]]) -> str:
        roll = rng.random()
        running = 0.0
        for value, prob in table:
            running += prob
            if roll <= running:
                return value
        return table[-1][0]

    def sample_secret(self, seed: int) -> dict:
        rng = random.Random(seed)
        remaining_length = self.length - len(self.prefix)
        api_key = self.prefix + self._random_body(rng, remaining_length)

        service = self._weighted_pick(rng, self._services)
        region = self._weighted_pick(rng, self._regions)
        account_hint = f"{rng.randint(100000000000, 999999999999)}"

        return {
            "aws_api_key": api_key,
            "service": service,
            "region": region,
            "account_hint": account_hint,
            "access_scope": "read-only" if rng.random() < 0.7 else "mixed",
        }

    def sample_multiple(self, count: int, base_seed: int) -> list[dict]:
        return [self.sample_secret(base_seed + i * 7919) for i in range(count)]


class FakeKeyGenerator:
    """Compatibility wrapper for existing callers expecting key strings."""

    def __init__(self):
        self.dte = CloudSecretDTE()

    def generate_key(self) -> str:
        seed = random.getrandbits(64)
        return self.dte.sample_secret(seed)["aws_api_key"]

    def generate_multiple(self, count: int) -> list[str]:
        seed = random.getrandbits(64)
        return [item["aws_api_key"] for item in self.dte.sample_multiple(count, seed)]