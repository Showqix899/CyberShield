from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from django.db.models import Count
from django.contrib.auth.models import User
from django.utils import timezone
from scanner.models import Scan,Vulnerability, PortResult




@login_required
def dashboard(request):

    scans = Scan.objects.filter(user=request.user)

    total_scans = scans.count()

    total_ports = PortResult.objects.filter(
        scan__user=request.user
    ).count()

    total_vulnerabilities = Vulnerability.objects.filter(
        scan__user=request.user
    ).count()

    high_risk = scans.filter(
        risk_score__gte=70
    ).count()

    recent_scans = scans.order_by("-created_at")[:5]

    recent_vulnerabilities = Vulnerability.objects.filter(
        scan__user=request.user
    ).order_by("-id")[:5]

    severity = list(
        Vulnerability.objects.filter(
            scan__user=request.user
        ).values("severity").annotate(
            total=Count("id")
        )
    )

    context = {

        "total_scans": total_scans,
        "total_ports": total_ports,
        "total_vulnerabilities": total_vulnerabilities,
        "high_risk": high_risk,

        "recent_scans": recent_scans,
        "recent_vulnerabilities": recent_vulnerabilities,

        "severity": severity,

    }

    return render(
        request,
        "dashboard/dashboard.html",
        context,
    )
    
