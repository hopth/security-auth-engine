from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import LoginAttemptTracker

@csrf_exempt
def login_view(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed. Use POST."}, status=405)

    ip_address = request.META.get('REMOTE_ADDR')

    # Query database for existing failures
    tracker = LoginAttemptTracker.objects.filter(ip_address=ip_address).first()

    # Security Lockout Gate
    if tracker and tracker.failed_attempts >= 3:
        return JsonResponse({
            "error": "Access Denied. Account locked due to multiple failed login attempts."
        }, status=403)

    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid request payload syntax."}, status=400)

    # 1. Simulate a database credential match check
    if username == "admin" and password == "secure123":
        if tracker:
            tracker.failed_attempts = 0
            tracker.save()
        return JsonResponse({"status": "authenticated", "message": "Access granted!"})
        
    else:
        # 2. Handle password failure tracking
        tracker_record, created = LoginAttemptTracker.objects.get_or_create(
            ip_address=ip_address,
            username=username or "unknown",
            defaults={'failed_attempts': 0}
        )
        
        # 3. Step up counter
        tracker_record.failed_attempts += 1
        tracker_record.save()

        # 4. Throw unauthorized response
        strikes_left = 3 - tracker_record.failed_attempts
        return JsonResponse({
            "status": "unauthorized",
            "message": f"Invalid credentials. You have {max(0, strikes_left)} attempts remaining before system lockout."
        }, status=401)
