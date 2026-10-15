from __future__ import annotations

import io
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError


@dataclass(frozen=True)
class OcrResult:
    text: str
    ok: bool
    error: str | None = None


def normalize_image(data: bytes, mime: str) -> bytes:
    if mime not in {"image/png", "image/jpeg"}:
        raise ValueError("Only PNG and JPEG images are accepted")
    try:
        with Image.open(io.BytesIO(data)) as image:
            expected_format = {"image/png": "PNG", "image/jpeg": "JPEG"}[mime]
            if image.format != expected_format:
                raise ValueError("Image content does not match an allowed format")
            if image.width * image.height > 25_000_000:
                raise ValueError("Image dimensions exceed the 25 megapixel limit")
            clean = image.convert("RGB")
            output = io.BytesIO()
            clean.save(output, format="PNG")
            return output.getvalue()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Image could not be decoded") from exc


def extract(png_bytes: bytes) -> OcrResult:
    if os.getenv("OCR_MODE", "stub").lower() != "tesseract":
        return OcrResult("", False, "OCR is unavailable in stub mode")
    try:
        import pytesseract

        configured = os.getenv("TESSERACT_CMD") or shutil.which("tesseract")
        if not configured and Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe").is_file():
            configured = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if configured:
            pytesseract.pytesseract.tesseract_cmd = configured
        with Image.open(io.BytesIO(png_bytes)) as image:
            text = pytesseract.image_to_string(
                image, timeout=5, config=os.getenv("TESSERACT_CONFIG", "--psm 6")
            )
        return OcrResult(text, True)
    except Exception as exc:
        return OcrResult("", False, f"OCR failed: {type(exc).__name__}")
