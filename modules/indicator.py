from typing import Any

class Indicator:

    def __init__(self, type: str, content: Any, domain: str | None = None):
        self.type = type
        self.content = content
        self.domain = domain

    def to_dict(self):
        return {
        "indicator_type": self.type,
        "indicator_content": self.content,
    }
    