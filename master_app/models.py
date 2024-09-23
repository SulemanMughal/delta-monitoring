from django.db import models

# Create your models here.
import uuid


# class Document(models.Model):
#     name = models.CharField(max_length=50, blank=False, null=False, unique=True, default="")
#     document = models.FileField(upload_to='documents/')
#     created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    


#     class Meta:
#         ordering = ['-created_at']

#     def __str__(self):
#         return "{}".format(self.name)



class Packets(models.Model):
    # id = models.Big(primary_key=True, editable=False, unique=True)
    # Document = models.ForeignKey(Document, on_delete=models.CASCADE, blank=True, null=True)
    destination_ip = models.CharField(max_length=50,  null=True,db_index=True)
    source_ip = models.CharField(max_length=50,  null=True,db_index=True)
    # type = models.CharField(max_length=5,  null=True, default="")
    protocol = models.CharField(max_length=5,  null=True)
    src_port = models.PositiveIntegerField(default=0)
    dst_port = models.PositiveIntegerField(default=0)
    payload = models.TextField( null=True, default="")
    date = models.DateField(auto_now_add=True, db_index=True)
    time = models.TimeField(auto_now_add=True, db_index=True)
    # is_namp = models.BooleanField( blank=True, null=True, default=False)
    # summary = models.TextField(blank=True, null=True, default="")
    # raw_data = models.TextField(blank=True, null=True, default="", verbose_name="Packet Raw Data")
    # attack_name = models.CharField(max_length=255, blank=True,  default="", verbose_name="Attack Name")
    # is_firewall_log = models.BooleanField(blank=True,  default=False) # plz made changes in fortinet_logs.py for this field accordingly
    # timestamp = models.DateTimeField("Created at",auto_now_add=True, db_index=True)
    # # 
    


        


    # class Meta:
    #     ordering = ['-timestamp']

    
    def __str__(self):
        return f"Src IP : {self.source_ip}\nSrc Port : {self.src_port}\nDst IP : {self.destination_ip}\nDst Port:{self.dst_port}"
    

# class OSDetecion(models.Model):
#     os_name = models.CharField(max_length=255, blank=True, null=True, db_index=True)


class External(models.Model):
    destination_ip = models.CharField(max_length=50,  null=True,db_index=True)
    source_ip = models.CharField(max_length=50,  null=True,db_index=True)
    protocol = models.CharField(max_length=50,  null=True)
    src_port = models.PositiveIntegerField(default=0)
    dst_port = models.PositiveIntegerField(default=0)
    payload = models.TextField( null=True, default="")
    date = models.DateField(auto_now_add=True, db_index=True)
    time = models.TimeField(auto_now_add=True, db_index=True)
    attack_name = models.CharField(max_length=255, blank=True,  default="", verbose_name="Attack Name")
    log_id = models.PositiveBigIntegerField(default=0, blank=True, null=True, db_index=True, unique=True)
    severity = models.CharField(max_length=10, blank=True,  default="High", verbose_name="Severity")
    





# postgre query to get different types of dst_port with counter
# select dst_port, count(dst_port) from master_app_packets group by dst_port order by count(dst_port) desc;