import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scamshield.settings')
django.setup()

from scanner.services import analyze_url

result = analyze_url('http://dfwdiesel.net')
print(json.dumps(result, indent=2))
