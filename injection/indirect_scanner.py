from injection.rules import findings


def scan_document(text: str) -> list[dict[str, object]]:
    return [
        item.model_dump(mode="json")
        for item in findings(text, "document")
    ]
