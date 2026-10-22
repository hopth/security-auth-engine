from django.db import models

class LoginAttemptTracker(models.Model):
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150)
    failed_attempts = models.IntegerField(default=0)
    last_attempt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address} - {self.username} (Fails: {self.failed_attempts})"
