from django.db import models
from django.contrib.auth.models import User
#scan model 
class Scan(models.Model):

    SCAN_TYPES = [
        ("website", "Website"),
        ("ip", "IP Address"),
        ("domain", "Domain"),
    ]

    STATUS = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    target = models.CharField(max_length=255)
    
    ip_address = models.GenericIPAddressField(
    null=True,
    blank=True
    )

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPES
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS,
        default="pending"
    )

    risk_score = models.IntegerField(default=0)
    
    ssl_enabled = models.BooleanField(default=False)

    ssl_issuer = models.CharField(
        max_length=255,
        blank=True
    )

    ssl_expiry = models.DateTimeField(
        null=True,
        blank=True
    )

    tls_version = models.CharField(
        max_length=50,
        blank=True
    )
    
    ai_recommendation = models.TextField(
        blank=True,
        null=True,
    )

    ai_generated_at = models.DateTimeField(
        blank=True,
        null=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    completed_at = models.DateTimeField(
        null=True,
        blank=True
    )

    def __str__(self):
        return self.target
    


#vulnerability model
class Vulnerability(models.Model):

    SEVERITY = [
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Info", "Info"),
    ]

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="vulnerabilities"
    )

    title = models.CharField(max_length=200)

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY
    )

    port = models.IntegerField(
        null=True,
        blank=True
    )

    service = models.CharField(
        max_length=100,
        blank=True
    )

    description = models.TextField()

    recommendation = models.TextField()

    def __str__(self):
        return self.title
    
    
    
class PortResult(models.Model):

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="ports"
    )

    port = models.IntegerField()

    service = models.CharField(
        max_length=100
    )

    status = models.CharField(
        max_length=20,
        default="Open"
    )
    
    banner = models.TextField(
        blank=True,
        null=True
    )

    version = models.CharField(
        max_length=255,
        blank=True
    )

    def __str__(self):
        return f"{self.port} ({self.service})"
    
    
    
    
class HttpHeader(models.Model):

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="headers"
    )

    name = models.CharField(max_length=100)

    value = models.TextField()
    
    
class DNSRecord(models.Model):

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="dns_records"
    )

    record_type = models.CharField(max_length=20)

    value = models.TextField()

    def __str__(self):
        return f"{self.record_type}: {self.value}"
    
    
class CVE(models.Model):

    software = models.CharField(max_length=100)

    version = models.CharField(max_length=50)

    cve_id = models.CharField(max_length=30)

    severity = models.CharField(max_length=20)

    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1
    )

    description = models.TextField()

    recommendation = models.TextField()

    def __str__(self):
        return self.cve_id