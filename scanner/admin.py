from django.contrib import admin
from .models import Scan, PortResult, Vulnerability,DNSRecord,CVE

admin.site.register(Scan)
admin.site.register(PortResult)
admin.site.register(Vulnerability)
admin.site.register(DNSRecord)
admin.site.register(CVE)