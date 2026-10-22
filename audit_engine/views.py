from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def login_view(request):
    # Task 1: Enforce HTTP Validation (Only allow POST requests)
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed. Use POST."}, status=405)

    # Task 2: Extract Netloc Metadata (Grab the visitor's IP address)
    ip_address = request.META.get('REMOTE_ADDR')

    # Task 3: Handle JSON Payload Serialization
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid request payload syntax."}, status=400)

    # Task 4: Base Execution Handshake Response
    return JsonResponse({
        "status": "gate_checked",
        "detected_ip": ip_address,
        "target_user": username
    })
