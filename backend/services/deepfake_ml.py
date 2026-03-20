import asyncio
import httpx
from io import BytesIO
from backend.config import settings

# Lazy-load the model so startup is fast
_pipeline = None
_ml_available = True


def _get_pipeline():
    global _pipeline, _ml_available
    if _pipeline is None:
        try:
            from transformers import pipeline
            from PIL import Image
            _pipeline = pipeline(
                "image-classification",
                model=settings.DEEPFAKE_MODEL_NAME,
                device=-1  # CPU; set to 0 for GPU
            )
        except Exception:
            _ml_available = False
            return None
    return _pipeline


async def analyze_media(url: str) -> dict:
    """
    Download an image from the given URL and run it through the
    deepfake detection model. Returns confidence score and verdict.
    Falls back to demo data if ML dependencies are unavailable.
    """
    # Step 1: Download the image
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "image" not in content_type:
                return {
                    "error": f"URL does not point to a supported image. Content-Type: {content_type}",
                    "url": url
                }
            image_bytes = resp.content
    except httpx.RequestError as e:
        return {"error": f"Could not download media: {str(e)}", "url": url}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code} fetching media.", "url": url}

    # Step 2: Try ML inference, fall back to mock if unavailable
    pipe = _get_pipeline()
    if pipe is None or not _ml_available:
        return _mock_deepfake_result(url)

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _run_inference, image_bytes)
        return {**result, "url": url}
    except Exception as e:
        return {"error": f"Inference failed: {str(e)}", "url": url}


def _run_inference(image_bytes: bytes) -> dict:
    """Synchronous inference call, run inside executor."""
    from PIL import Image
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    pipe = _get_pipeline()
    predictions = pipe(image)

    fake_score = 0.0
    real_score = 0.0

    for pred in predictions:
        label = pred["label"].lower()
        score = pred["score"]
        if "fake" in label or "deepfake" in label or "manipulated" in label:
            fake_score = score
        elif "real" in label or "authentic" in label:
            real_score = score

    confidence_pct = round(fake_score * 100, 2)
    verdict = "FAKE" if fake_score > 0.5 else "REAL"

    return {
        "verdict": verdict,
        "confidence_pct": confidence_pct,
        "fake_score": round(fake_score, 4),
        "real_score": round(real_score, 4),
        "raw_predictions": predictions,
    }


def _mock_deepfake_result(url: str) -> dict:
    """
    Demo response when torch/transformers are not installed.
    Returns a randomised but realistic-looking analysis result.
    """
    import random
    fake_score = round(random.uniform(0.55, 0.98), 4)
    real_score = round(1.0 - fake_score, 4)
    confidence_pct = round(fake_score * 100, 2)
    verdict = "FAKE" if fake_score > 0.5 else "REAL"

    return {
        "url": url,
        "verdict": verdict,
        "confidence_pct": confidence_pct,
        "fake_score": fake_score,
        "real_score": real_score,
        "note": "DEMO MODE — Install torch + transformers for real ML inference.",
    }

