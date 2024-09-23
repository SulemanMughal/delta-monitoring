from django.contrib import admin

# Register your models here.



from .models import *


from .actions import export_selected_objects


admin.site.register(Document)
# admin.site.register(Packets)


class PacketAdmin(admin.ModelAdmin):
    list_display = [
        # "id", 
        "date",
        "time",
        # "timestamp",
        # "is_namp",
        # "payload",
        "destination_ip",
        "source_ip",
        # "type",
        "protocol",
        "src_port",
        "dst_port",
        # "is_firewall_log"
        # "tcp_sport",
        # "tcp_dport"
    ]
    

    # readonly_fields = ["tickets_left"]

    export_selected_objects.short_description = "Export selected objects as CSV"
    actions = [export_selected_objects]




# class YourModelAdmin(admin.ModelAdmin):
#     actions = [export_selected_objects]

admin.site.register(Packets, PacketAdmin)
admin.site.register(External)