from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value):
        if isinstance(value, Severity):
            return value
        return cls[str(value).upper()]


@dataclass
class Finding:
    check: str
    title: str
    severity: Severity
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
