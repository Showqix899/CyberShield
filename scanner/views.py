from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404

from .forms import ScanForm
from .services.engine import ScanEngine
from django.shortcuts import redirect
from .models import Scan
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse
from .services.pdf_report import PDFReport




@login_required
def new_scan(request):

    result = None
    if request.method == "POST":

        form = ScanForm(request.POST)

        if form.is_valid():

            target = form.cleaned_data["target"]

            engine = ScanEngine()

            result = engine.run(
                request.user,
                target,
            )

            if result["success"]:

                return redirect(
                    "scan_detail",
                    scan_id=result["scan"].id,
                )

    else:

        form = ScanForm()

    return render(
        request,
        "scanner/new_scan.html",
        {
            "form": form,
            "result": result,
        },
    )


@login_required
def scan_history(request):

    scans = Scan.objects.filter(user=request.user)

    query = request.GET.get("q", "").strip()
    if query:
        scans = scans.filter(
            Q(target__icontains=query) | Q(ip_address__icontains=query)
        )

    status = request.GET.get("status", "").strip()
    if status:
        scans = scans.filter(status=status)

    sort = request.GET.get("sort", "").strip()
    if sort == "risk_high":
        scans = scans.order_by("-risk_score", "-created_at")
    elif sort == "risk_low":
        scans = scans.order_by("risk_score", "-created_at")
    else:
        scans = scans.order_by("-created_at")

    paginator = Paginator(scans, 10)
    page_number = request.GET.get("page")
    scans_page = paginator.get_page(page_number)

    querystring = request.GET.copy()
    querystring.pop("page", None)

    context = {
        "scans": scans_page,
        "query": query,
        "selected_status": status,
        "selected_sort": sort,
        "status_choices": Scan.STATUS,
        "querystring": querystring.urlencode(),
    }

    return render(request, "scanner/history.html", context)



@login_required
def scan_detail(request, scan_id):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user
    )

    ports = scan.ports.all()
    vulnerabilities = scan.vulnerabilities.all()
    dns_records = scan.dns_records.all()

    return render(
        request,
        "scanner/detail.html",
        {
            "scan": scan,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "dns_records": dns_records,
        },
    )
    
    
    
    
@login_required
def download_report(request, scan_id):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user,
    )

    pdf = PDFReport().generate(scan)

    response = HttpResponse(
        pdf,
        content_type="application/pdf",
    )

    response[
        "Content-Disposition"
    ] = f'attachment; filename="scan_{scan.id}.pdf"'

    return response

def delete_scan(request, scan_id):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user,
    )

    if request.method == "POST":
        scan.delete()
        return redirect("scan_history")

    return render(
        request,
        "scanner/confirm_delete.html",
        {
            "scan": scan,
        },
    )