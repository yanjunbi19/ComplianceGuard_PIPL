from PIL import Image
import imagehash
from io import BytesIO
from io import BytesIO
from PIL import Image
import numpy as np
import imagehash


def img_hash_distance(img_b, img_a, debug: bool = False):
    """
    Compute perceptual hash distance (phash) between two images.

    Accepts:
    - bytes / bytearray
    - io.BytesIO
    - PIL.Image.Image
    - numpy.ndarray (H,W), (H,W,3), (H,W,4) uint8/float

    Returns:
    - int: Hamming distance of phash
    """

    def _to_pil(x):
        if x is None:
            raise TypeError("img is None")

        # bytes-like -> PIL
        if isinstance(x, (bytes, bytearray)):
            return Image.open(BytesIO(x)).convert("RGB")

        # BytesIO -> PIL
        if isinstance(x, BytesIO):
            x.seek(0)
            return Image.open(x).convert("RGB")

        # PIL -> ensure RGB
        if isinstance(x, Image.Image):
            return x.convert("RGB")

        # numpy -> PIL
        if isinstance(x, np.ndarray):
            arr = x
            if arr.ndim == 2:
                arr = np.stack([arr, arr, arr], axis=-1)
            elif arr.ndim == 3 and arr.shape[2] == 4:
                arr = arr[:, :, :3]

            if arr.dtype != np.uint8:
                # if float image in [0,1], scale; otherwise clip
                if np.issubdtype(arr.dtype, np.floating):
                    arr = (arr * 255.0).clip(0, 255).astype(np.uint8)
                else:
                    arr = arr.clip(0, 255).astype(np.uint8)

            return Image.fromarray(arr, mode="RGB")

        raise TypeError(f"Unsupported image type: {type(x)}")

    pil_img_a = _to_pil(img_a)
    pil_img_b = _to_pil(img_b)

    image_a_hash = imagehash.phash(pil_img_a)
    image_b_hash = imagehash.phash(pil_img_b)
    distance = image_a_hash - image_b_hash

    if debug:
        print("similarity is", distance)

    return distance
