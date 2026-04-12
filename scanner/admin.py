from django.contrib import admin
from .models import UrlScan

@admin.register(UrlScan)
class UrlScanAdmin(admin.ModelAdmin):
    list_display = ("id", "url", "verdict", "score", "created_at")
    search_fields = ("url", "normalized_url", "verdict")
    list_filter = ("verdict", "created_at")
    ordering = ("-created_at",)