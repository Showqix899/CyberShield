from django import forms

class ScanForm(forms.Form):

    target = forms.CharField(
        label="Target",
        max_length=255,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "example.com or 192.168.1.10"
        })
    )