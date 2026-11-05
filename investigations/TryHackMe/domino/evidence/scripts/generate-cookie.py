import hmac, hashlib, base64, json

secret = "nexus_app_k3y_2024"
user_id = 1

payload = base64.b64encode(json.dumps({"user_id": user_id}).encode()).decode()
sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
cookie = f"{payload}.{sig}"

print(cookie)