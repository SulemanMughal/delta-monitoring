
# from django.contrib import admin
from django.http import HttpResponse
from django.utils.text import slugify

import csv



from .models import *

def export_selected_objects(modeladmin, request, queryset):
    """
    Custom export action to export selected objects as a CSV file.
    """
    # Customize this function based on the fields you want to include in the export
    headers = [
        'id',
        'destination_ip',
        'source_ip',
        'type',
        'protocol',
        # 'tcp_sport',
        # 'tcp_dport',
        'payload',
        'timestamp'
        
        # Add more fields as needed
    ]

    rows = [
        headers,
        *[list(map(str, [getattr(obj, field) for field in headers])) for obj in queryset]
    ]

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename={slugify(modeladmin.model.__name__)}_export.csv'

    # Write CSV content to the response
    csv_writer = csv.writer(response)
    csv_writer.writerows(rows)

    return response



