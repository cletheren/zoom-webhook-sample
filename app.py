import hashlib
import hmac
import os

from dotenv import load_dotenv
from flask import Flask, request, json

app = Flask(__name__)

# Get the webhook token from .env, populated using information from your marketplace app
load_dotenv()
webhook_token = os.getenv("WEBHOOK_TOKEN")


def source_is_zoom() -> bool:
    """Validate that Zoom is the source of the webhook
    https://developers.zoom.us/docs/api/rest/webhook-reference/#validate-your-webhook-endpoint
    """
    payload = request.get_data()
    timestamp = request.headers.get("X-Zm-Request-Timestamp")
    signature = request.headers.get("X-Zm-Signature")
    if timestamp and signature:
        validation_message = f"v0:{timestamp}:{payload.decode()}"
        hash = hmac.new(
            webhook_token.encode(), validation_message.encode(), hashlib.sha256
        ).hexdigest()
        return f"v0={hash}" == signature
    return False


def endpoint_validation() -> dict[str, str]:
    """Perform periodic endpoint validation
    https://developers.zoom.us/docs/api/rest/webhook-reference/#validate-your-webhook-endpoint
    """
    payload = request.get_json()
    plain_token = payload["payload"]["plainToken"]
    validation_hash = hmac.new(
        webhook_token.encode(), plain_token.encode(), hashlib.sha256
    ).hexdigest()
    return {"plainToken": plain_token, "encryptedToken": validation_hash}


@app.route("/webhook", methods=["POST"])
def contact_center():
    payload = request.get_json()

    if not source_is_zoom():
        return app.response_class(status=404)

    if payload["event"] == "endpoint.url_validation":
        validation_payload = endpoint_validation()
        return app.response_class(
            content_type="application/json",
            response=validation_payload,
            status=204,
        )

    # If we've got this far, it's a validated webhook that we output to the console
    print(json.dumps(payload, indent=4))
    return app.response_class(status=200)


if __name__ == "__main__":
    app.run(port=8000, debug=True)
