from django.db import models
from django.contrib.auth.models import User

class UrlScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    url = models.URLField()
    normalized_url = models.URLField(blank=True)
    verdict = models.CharField(max_length=50, blank=True)
    score = models.IntegerField(default=0)
    report_json = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class IpScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    version = models.CharField(max_length=10, blank=True)
    reverse_dns = models.CharField(max_length=255, blank=True)
    is_private = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.subject} from {self.email}"

class TextScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    text_content = models.TextField()
    verdict = models.CharField(max_length=50, blank=True)
    score = models.IntegerField(default=0)
    reasons_json = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Text Scan {self.id}"

class FileScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, blank=True) # SHA-256
    verdict = models.CharField(max_length=50, blank=True)
    score = models.IntegerField(default=0) # Detection count
    total_engines = models.IntegerField(default=0)
    report_json = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file_name

class PortScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    target = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    open_ports_json = models.TextField(default='[]')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan for {self.target}"


class CommunityPost(models.Model):
    SCAM_TYPE_CHOICES = [
        ('website', 'Website / Phishing Link'),
        ('qr_code', 'QR Code Scam'),
        ('sms', 'SMS / Text Message'),
        ('phone', 'Phone Call'),
        ('email', 'Email Scam'),
        ('social', 'Social Media'),
        ('payment', 'Payment / UPI Fraud'),
        ('other', 'Other'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='community_posts')
    is_anonymous = models.BooleanField(default=False)
    title = models.CharField(max_length=200)
    scam_type = models.CharField(max_length=20, choices=SCAM_TYPE_CHOICES, default='other')
    scam_source = models.CharField(max_length=500, blank=True, help_text='URL, phone number, or entity that scammed you')
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def display_author(self):
        if self.is_anonymous:
            return 'Anonymous Shield User'
        return self.user.username


class CommunityComment(models.Model):
    post = models.ForeignKey(CommunityPost, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='community_comments')
    is_anonymous = models.BooleanField(default=False)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Comment on {self.post.title}"

    def display_author(self):
        if self.is_anonymous:
            return 'Anonymous Shield User'
        return self.user.username