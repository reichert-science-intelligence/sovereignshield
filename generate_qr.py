"""Regenerate StarGuard Mobile QR code as PNG base64."""
import base64
from io import BytesIO

import qrcode

url = "https://rreichert-starguardai.hf.space"
qr = qrcode.make(url)
buf = BytesIO()
qr.save(buf, format="PNG")
b64 = base64.b64encode(buf.getvalue()).decode()

out_path = "Artifacts/project/sovereignshield/assets/QR_Mobile_Tiny_Sized.b64.txt"
with open(out_path, "w") as f:
    f.write(b64)
print("Done:", b64[:20])
