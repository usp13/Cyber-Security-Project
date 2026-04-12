from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('email',)


class UrlScanForm(forms.Form):
    url = forms.CharField(
        label='URL',
        max_length=2000,
        widget=forms.TextInput(attrs={
            'class': 'input-control',
            'placeholder': 'Paste a suspicious URL here, for example https://example.com/login',
        })
    )


class IPLookupForm(forms.Form):
    ip_address = forms.CharField(
        label='IP Address',
        max_length=64,
        widget=forms.TextInput(attrs={
            'class': 'input-control',
            'placeholder': 'Enter an IPv4 or IPv6 address',
        })
    )


class PasswordGeneratorForm(forms.Form):
    length = forms.IntegerField(min_value=8, max_value=64, initial=16)
    include_symbols = forms.BooleanField(required=False, initial=True)
    include_digits = forms.BooleanField(required=False, initial=True)
    include_uppercase = forms.BooleanField(required=False, initial=True)

class TextScanForm(forms.Form):
    text_content = forms.CharField(
        label='Message Content',
        widget=forms.Textarea(attrs={
            'class': 'input-control',
            'placeholder': 'Paste suspicious SMS or Email text here. E.g., "URGENT: Your account has been suspended..."',
            'rows': 6
        })
    )
