from collections import defaultdict
from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, request, jsonify
import time
import aiohttp
from aiohttp import ClientTimeout, ClientError, ClientConnectionError
from urllib.parse import urlparse
import socket
import ipaddress

app = Flask(__name__)

RATE_LIMIT = {
    'TIME': 300,  # seconds to clean user requests limit
    'MAX_REQUESTS': 300,  # user requests limit
    'MAX_BODY_SIZE': 10 * 1024 * 1024,  # 10 MB max size of response
    'REQUEST_TIMEOUT': 15  # seconds until request will be timed out
}

request_counts = defaultdict(list)

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False

        host = parsed.hostname
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)

        return not (
            ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )
    except Exception:
        return False

@app.before_request
def limit_request_size_and_rate_limit():
    ip = request.remote_addr
    current_time = time.time()

    if request.content_length and request.content_length > RATE_LIMIT['MAX_BODY_SIZE']:
        raise RequestEntityTooLarge(f"Request body is too large. Max size is {RATE_LIMIT['MAX_BODY_SIZE']} bytes.")

    request_counts[ip] = [t for t in request_counts[ip] if current_time - t < RATE_LIMIT['TIME']]

    if len(request_counts[ip]) >= RATE_LIMIT['MAX_REQUESTS']:
        next_available_time = max(0, RATE_LIMIT['TIME'] - (current_time - request_counts[ip][0]))
        return jsonify({
            "error": "Rate limit exceeded",
            "message": f"Please try again in {int(next_available_time)} seconds."
        }), 429

    request_counts[ip].append(current_time)

@app.route('/', methods=['GET'])
async def proxy():
    target_url = request.args.get('url')
    
    if not target_url:
        return jsonify({"error": "URL parameter is missing", "message": "Provide a valid 'url' parameter."}), 400

    if not is_safe_url(target_url):
        return jsonify({"error": "Forbidden URL", "message": "This URL is not allowed."}), 403

    timeout = ClientTimeout(total=RATE_LIMIT['REQUEST_TIMEOUT'])

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(target_url) as response:
                data = await response.text()

                if response.status != 200:
                    return jsonify({"error": f"Error occurred: {data}"}), response.status

                return jsonify({"message": "Request successful", "data": data}), 200

    except aiohttp.ClientTimeout:
        return jsonify({"error": "Request timed out", "message": "The request took too long to complete. Please try again later."}), 504
    except ClientConnectionError:
        return jsonify({"error": "Connection error", "message": "Failed to establish a connection to the target URL."}), 502
    except ClientError as e:
        return jsonify({"error": "Request error", "message": f"An error occurred while processing the request: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": "Unknown error", "message": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7777, debug=True)
