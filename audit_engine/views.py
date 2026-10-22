from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
import json
from .models import LoginAttemptTracker

@csrf_exempt
def login_view(request):
    # 1. Enforce HTTP Validation (Only allow POST methods)
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed. Use POST."}, status=405)

    # 2. Extract network socket metadata (Grab caller's IP address)
    ip_address = request.META.get('REMOTE_ADDR')

    # 3. Query the database for an existing failure record matching this IP
    tracker = LoginAttemptTracker.objects.filter(ip_address=ip_address).first()

    # 4. Time-Aware Security Gate Interception
    if tracker and tracker.failed_attempts >= 3:
        # Calculate how much time has passed since their absolute last failure
        time_elapsed = timezone.now() - tracker.last_attempt
        
        # Check if the penalty cooldown window (15 minutes / 900 seconds) has expired
        if time_elapsed.total_seconds() > 900:
            # Cooldown over! Reset their database record row back to a fresh slate
            tracker.failed_attempts = 0
            tracker.save()
        else:
            # Still in penalty window. Calculate remaining seconds for the warning feedback
            time_left = int(900 - time_elapsed.total_seconds())
            minutes = time_left // 60
            seconds = time_left % 60
            return JsonResponse({
                "error": f"Access Denied. Account locked. Cooldown active for another {minutes}m {seconds}s."
            }, status=403)

    # 5. Handle JSON Data Deserialization
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid request payload syntax."}, status=400)

    # 6. Evaluate Credentials Against Identity Store
    if username == "admin" and password == "secure123":
        # Clear out any old failure strikes upon a valid login
        if tracker:
            tracker.failed_attempts = 0
            tracker.save()
        return JsonResponse({"status": "authenticated", "message": "Access granted!"})
        
    else:
        # 7. Credential failure tracking mechanism
        tracker_record, created = LoginAttemptTracker.objects.get_or_create(
            ip_address=ip_address,
            username=username or "unknown",
            defaults={'failed_attempts': 0}
        )
        
        # Step up failure tally counter
        tracker_record.failed_attempts += 1
        tracker_record.save()

        # Throw unauthorized warning metadata response
        strikes_left = 3 - tracker_record.failed_attempts
        return JsonResponse({
            "status": "unauthorized",
            "message": f"Invalid credentials. You have {max(0, strikes_left)} attempts remaining before system lockout."
        }, status=401)
