from typing import Any

class Indicator:

    def __init__(self, type: str, content: Any):
        self.type = type
        self.content = content

    def to_dict(self):
        return {
        "indicator_type": self.type,
        "indicator_content": self.content,
    }