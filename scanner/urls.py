from django.urls import path
from .views import new_scan, scan_history,scan_detail,download_report,delete_scan,generate_ai_recommendation,nmap_scan

urlpatterns = [
    path("new/", new_scan, name="new_scan"),
    path("history/", scan_history, name="scan_history"),
    path("<int:scan_id>/", scan_detail, name="scan_detail"),
    path(
    "<int:scan_id>/report/",
    download_report,
    name="download_report",
    ),
    path(
    "<int:scan_id>/delete/",
    delete_scan,
    name="delete_scan",
    ),
    path(
    "<int:scan_id>/ai-recommendation/",
    generate_ai_recommendation,
    name="generate_ai_recommendation",
    ),
    path(
    "nmap-scan/",
    nmap_scan,
    name="nmap_scan",
    ),
    

]