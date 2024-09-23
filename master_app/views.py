# from django.shortcuts import render

import os
import datetime
import json
import traceback
import subprocess
from io import BytesIO
from django.template.loader import get_template
from django.db.models import Q
import shutil

from django.conf import settings

from xhtml2pdf import pisa

from django.core import serializers

from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse, HttpResponse

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.shortcuts import render, redirect

from django.urls import reverse

# from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.views.decorators.csrf import csrf_exempt

from .models import (
    # Document,
    Packets,
    External
)

from django.db.models import Count

from . import monitoring

from django.views.decorators.cache import cache_page

import pathlib




from .helpers import (
    read_pcap_file,
    get_protocol_name,
    proto_name_by_num,
    read_payload,
    get_packet_src_ip,
    get_packet_dst_ip
)


from .utils import (
    ETHERNET_IP_VERSION_TYPE,
    network_conversation,
    read_list,
    read_json,
    read_json_key,
    get_common_ip_addresses,
    read_mac_address,
    get_user_agents
    
)

# from django.shortcuts import render, redirect
# from django.contrib.auth import authenticate, login, logout



# Create your views here.


from .forms import (
    loginForm
)

def index(request):
    template_name = "master_app/index.html"
    if request.user.is_authenticated:
        return redirect("dashboard_url")
    context = {

    }
    return render(request, template_name, context)



def UserLoginView(request):
    template_name = "master_app/login.html"
    if request.user.is_authenticated:
        return redirect("index")
    else:
        if request.method == "POST":
            form = loginForm(request.POST)
            valuenext = request.POST.get('next')
            if form.is_valid():
                try:
                    u = authenticate(
                        request,
                        username=form.cleaned_data["username"],
                        password=form.cleaned_data["password"]
                    )
                    if u is not None:
                        if u.is_active:
                            login(request, u)
                            if len(valuenext) != 0 and valuenext is not None:
                                return redirect(valuenext)
                            else:
                                return redirect("dashboard_url")
                        else:
                            messages.error(
                                request, "User does not verify himself or he has been blocked from using our services due to violation of our terms and conditions.")
                    else:
                        messages.error(
                            request, "The username or password has been entered incorrectly.")
                except Exception as e:
                    messages.error(
                        request, "Please login after sometimes. Requests are not processed at this time.")
            else:
                messages.error(
                    request, "Please entered correct information for respective required fields.")

    form = loginForm()
    context = {
        "form": form,
        "section": True
    }
    return render(request, template_name, context)





# TODO  :   User Logout View
def UserLogoutView(request):
    logout(request)
    return redirect('index')


# @cache_page(60 * 15)
@login_required
def Dashboard(request):
    template_name = "master_app/dashboard.html"
    # document_counter = Document.objects.all().count()
    packets_counter = Packets.objects.all().count()
    # initial_documents = Document.objects.all()[:10]
    # initial_documents = serializers.serialize('python', initial_documents, ensure_ascii=False)
    # initial_documents_json = json.dumps(list(initial_documents), cls=DjangoJSONEncoder)
    initial_packets = Packets.objects.all()[:10]
    initial_packets = serializers.serialize('python', initial_packets, ensure_ascii=False)
    initial_packets_json = json.dumps(list(initial_packets), cls=DjangoJSONEncoder)

    # Highest Packets that has been sent by a single ip address from source
    # highest_packets_sent = Packets.objects.values('source_ip').annotate(count=Count('source_ip')).order_by('-count')[:10]
    # Source IP Address that has sent highest packets
    highest_packets_sent = Packets.objects.values('source_ip').annotate(count=Count('source_ip')).order_by('-count')[:10]
    highest_packets_sent = json.dumps(list(highest_packets_sent), cls=DjangoJSONEncoder)
    highest_packets_received = Packets.objects.values('destination_ip').annotate(count=Count('destination_ip')).order_by('-count')[:10]
    highest_packets_received = json.dumps(list(highest_packets_received), cls=DjangoJSONEncoder)
    # print(highest_packets_sent)
    # highest_packets_sent = serializers.serialize('python', highest_packets_sent, ensure_ascii=False)
    # highest_packets_sent = json.dumps(list(highest_packets_sent), cls=DjangoJSONEncoder)
    # print(highest_packets_sent)
    # print(highest_packets_sent)
    # # top ten highest packets with src port
    top_ten_src_prs = Packets.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count')[:10]
    top_ten_src_prs = json.dumps(list(top_ten_src_prs), cls=DjangoJSONEncoder)
    top_ten_dst_prs = Packets.objects.values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10]
    top_ten_dst_prs = json.dumps(list(top_ten_dst_prs), cls=DjangoJSONEncoder)
    # print(top_ten_src_prs)

    # disticnt src port with counter
    # highest_packets_sent = Packets.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count')[:10]
    # print(highest_packets_sent)

    # src port with highest number of packets
    src_port_highes_packet_sent = Packets.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count').first()

    # dst port with highest number of packets
    dst_port_highes_packet_sent = Packets.objects.values('dst_port').annotate(count=Count('dst_port')).order_by('-count').first()

    # print(dst_port_highes_packet_sent)

    # print(src_port_highes_packet_sent)

    # print(initial_documents_json)
    context = {
        # "document_counter" : document_counter,
        "packets_counter" : packets_counter,
        # "initial_documents_json" : initial_documents_json,
        "initial_packets_json" : initial_packets_json,
        "highest_packets_sent" : highest_packets_sent,
        "src_port_highes_packet_sent_label" : src_port_highes_packet_sent['src_port'] if src_port_highes_packet_sent else 0,
        "src_port_highes_packet_sent_value" : src_port_highes_packet_sent['count'] if src_port_highes_packet_sent else 0,
        "dst_port_highes_packet_sent_label" : dst_port_highes_packet_sent['dst_port'] if dst_port_highes_packet_sent else 0,
        "dst_port_highes_packet_sent_value" : dst_port_highes_packet_sent['count'] if dst_port_highes_packet_sent else 0,
        # "highest_packets_sent" : highest_packets_sent,
        "highest_packets_received" : highest_packets_received,
        "top_ten_src_prs" : top_ten_src_prs,
        "top_ten_dst_prs" : top_ten_dst_prs,
        "dashboard_section" : True, #   ?   For Active Dashboard Section


    }
    return render(request, template_name, context)





# ! Depreciated

@login_required
def document_upload_view(request):
    if request.method == 'POST' and request.FILES.get('myfile'):
        # print(request.POST, request.FILES)
        myFile = request.FILES.get('myfile')
        uploaded_document = Document.objects.create(
            document=myFile, 
            name=request.POST.get('name', myFile.name),
            observe_port=request.POST.get('port', 80),
        )
        uploaded_document.save()
        # print("asdasd")
        try:
            # print(uploaded_document.document.path)
            packets = read_pcap_file(uploaded_document.document.path , target_port=int(uploaded_document.observe_port))
            monitoring.save_packets(packets)
            # for packet in packets:
            #     x = read_payload(packet)
            #     if x is not None:
            #         # print(x, x.strip().isspace())
            #         if not x.isspace():
            #             Packets.objects.create(
            #                 Document=uploaded_document,
            #                 destination_ip=get_packet_dst_ip(packet),   
            #                 source_ip=get_packet_src_ip(packet),
            #                 type=ETHERNET_IP_VERSION_TYPE.get(str(packet.type), "Unknown"),
            #                 protocol=proto_name_by_num(packet.proto),
            #                 src_port=packet.sport,
            #                 dst_port=packet.dport,
            #                 payload=x,
            #             )

                # packet ethernet type 
                # print(ETHERNET_IP_VERSION_TYPE.get(str(packet.type), "Unknown"), packet.type)


                # packet protocol
                # proto_name = proto_name_by_num(packet.proto)
                # print(proto_name, packet.proto)

                # packet TCP sort port number
                # print(packet.sport)

                # packet TCP destination port number
                # print(packet.dport)

                # packet payload
                # print(read_payload(packet))


                # packet source ip address
                # print(packet.ip)
                # print(get_packet_src_ip(packet))


                # print(get_packet_dst_ip(packet))    
                




                # print

                # proto_name_by_num()

                # for i in range(257):
                #     proto_name = proto_name_by_num(i)
                #     if proto_name != "Protocol not found":
                #         print(i, proto_name)
                # print(packet.ip.proto)
                # print(get_protocol_name(int(packet.proto)s), packet.proto)

                # print(packet.summary())
                # print(
                #     packet.sport,
                #     packet.dport,
                # )
                # print(packet.ls(packet))
                # print(ls(packet))

            # print(len(packets))


            # Packets.objects.filter(document=uploaded_document).delete()
            
            
        except Exception as e:
            print(e)

        # print("uploaded")
        # messages.success(request, "Document uploaded successfully.")
        return redirect(reverse("document_details_url", kwargs={"document_id":uploaded_document.id}))            
        # document = serializers.serialize('python', [uploaded_document], ensure_ascii=False)
        # document_json = json.dumps(list(document), cls=DjangoJSONEncoder)
        # return JsonResponse({'document':document_json})
    template_name = "master_app/document_upload.html"
    context = {

    }
    return render(request, template_name, context)





# ! Depreciated
# Document Details
@login_required
def document_details(request, document_id):
    template_name = "master_app/document_details.html"
    try:
        document = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        messages.error(request, "Document does not exist.")
        return redirect("dashboard")
    except Exception as e:
        print(e)
        messages.error(request, "Something went wrong.")
        return redirect("dashboard")
    # print(document.ipaddresslogs_set.all())
    # logs = document.ipaddresslogs_set.all()s
    # operating_system_counter = IpAddressLogs.objects.values('operating_system').annotate(count=Count('operating_system')).order_by('-count')
    # city_counter = IpAddressLogs.objects.values('city').annotate(count=Count('city')).order_by('-count')
    # country_counter = IpAddressLogs.objects.values('country').annotate(count=Count('country')).order_by('-count')
    # locations_counter = IpAddressLogs.objects.values('latitude', 'longitude').annotate(count=Count('*')).order_by('-count')
    # region_counter = IpAddressLogs.objects.values('region').annotate(count=Count('region')).order_by('-count')
    context = {
        "document": document,
        # "logs" : logs,
        # "operating_system_counter" : operating_system_counter,
        # "city_counter" : city_counter,
        # "country_counter" : country_counter,
        # "locations_counter" : locations_counter,
        # "region_counter" : region_counter,
    }
    return render(request, template_name, context)



# ! Depreciated
# # ip address logs json
@login_required
def document_details_json(request, document_id):
    try:
        count = 0
        document = Document.objects.get(id=document_id)
        limit = int(request.GET.get('limit', 20))
        offset = int(request.GET.get('offset', 0))
        logs = document.packets_set.all()[offset : limit+offset].values('id', 'destination_ip', 'source_ip', 'timestamp', 'payload', 'type', 'protocol', 'tcp_sport', 'tcp_dport')
        count = document.packets_set.all().count()
        logs_json = json.dumps(list(logs), cls=DjangoJSONEncoder)
        try:
            return JsonResponse({'initial_packets':logs_json, 'count':count})
        except Exception as e:
            print(e)
            return JsonResponse({'initial_packets':None})
    except Exception as e:
        print(e)
        return JsonResponse({'initial_packets':None})
    



@login_required
def document_list_view(request):
    template_name = "master_app/document_list.html"
    documents = Document.objects.all()
    context = {
        "documents": documents
    }
    return render(request, template_name, context)




# document list json
@login_required
def document_list_json(request):
    documents = Document.objects.all().values('id', 'name', 'uploaded_at')
    documents_json = json.dumps(list(documents), cls=DjangoJSONEncoder)
    try:
        return JsonResponse({'documents':documents_json})
    except Exception as e:
        print(e)
        return JsonResponse({'documents':None}) 
    

@login_required
def search(request):
    template_name = "master_app/filter.html"
    search_query = request.GET.get('query', None)
    # if request.GET.get('search', None):
    #     # Packets.objects.filter(payloa=request.GET.get('document_id', None)).delete()
    # initial_packets = Packets.objects.all()[:100]
    # if search_query:
    #     initial_packets = Packets.objects.filter(payload__icontains=search_query).values('id', 'destination_ip', 'source_ip', 'payload')
    # else:
    #     initial_packets = Packets.objects.all()[:100].values('id', 'destination_ip', 'source_ip', 'payload')
    # initial_packets = json.dumps(list(initial_packets), cls=DjangoJSONEncoder)
    # print(initial_packets)
    context = {
        # "initial_packets": initial_packets,
        "search_query" : search_query,
        "search_section" : True, #   ?   For Active Search Section

    }
    return render(request, template_name, context)


@login_required
def saerch_json(request):

    # print(request.GET)

    current_page = request.GET.get('search_query[current_page]', 1)
    limit = int(settings.PAGE_SIZE)
    offset = (int(current_page) - 1) * limit
    count = Packets.objects.count()
    total_pages = count // limit
    # print(count, limit, offset, total_pages, current_page)
    if count % limit != 0:
        total_pages += 1
    try:
        initial_packets = Packets.objects.all().order_by('time')[offset : limit+offset].values('id' ,'source_ip', 'src_port', 'destination_ip', 'dst_port', 'payload', 'time')
        initial_packets = json.dumps(list(initial_packets), cls=DjangoJSONEncoder)
        return JsonResponse({'initial_packets':initial_packets, "pagination" : {
            "current_page" : current_page,
            "limit" : limit,
            "offset" : offset,
            "count" : count,
            "total_pages" : total_pages

        }})
    except Exception as e:
        traceback.print_exc()
        return JsonResponse({'initial_packets':None})




# Search Page Chart Data
@login_required
def search_chart_data(request):
    try:
        # Get Packets from current time to half an hour ago

        # print(request.GET.get("query[team_ip]", None))

        print(request.GET)

        team_ip = request.GET.get("query[team_id]", None)

        if team_ip:
            # get only first three octets of ip address
            team_ip = ".".join(team_ip.split(".")[:3])

        # print(request.GET)
            
        filtered_packets = None


        

        user_ip = request.GET.get("query[user_id]", None)
        src_port = request.GET.get("query[src_id]", None)
        dst_port = request.GET.get("query[dst_id]", None)
        challenge_id = request.GET.get("query[challenge_id]", None)
        query = request.GET.get("query[query]", None)
        startDate = request.GET.get("query[timeline][startDate]", None)
        endDate = request.GET.get("query[timeline][endDate]", None)
        # startDate = timeline["startDate"]
        # endDate = timeline["endDate"]
        # print(startDate, endDate)

        # '2024-2024-01-21 12:00:00' to into datetime object 
        # print(f'2024-{startDate}')

        startDate = datetime.datetime.strptime(f'{startDate}', '%Y-%m-%d %H:%M:%S')
        endDate = datetime.datetime.strptime(f'{endDate}', '%Y-%m-%d %H:%M:%S')
        
        startTime = startDate.time()
        startDate = startDate.date()
        endTime = endDate.time()
        endDate = endDate.date()
        isSameDate = startDate == endDate
        # print(isSameDate)
        # print(startDate == endDate)
        # print(startDate, endDate)


        # get start time and end time from timeline string like : '1/20 12:00 PM - 1/22 08:00 PM'
        # if timeline:
        #     # start_time = timeline.split("-")[0].strip()
        #     # end_time = timeline.split("-")[1].strip()
        #     start_str, end_str = map(str.strip, timeline.split('-'))
        #     # print(start_time, end_time)
        #     # print(datetime.datetime.strptime(start_time, '%m/%d %I:%M %p'))
        #     # print(datetime.datetime.strptime(end_time, '%m/%d %I:%M %p'))
        #     # start_time = datetime.datetime.strptime(start_time, '%m/%d %I:%M %p')
        #     # end_time = datetime.datetime.strptime(end_time, '%m/%d %I:%M %p')
        #     format_specifier = '%m/%d %I:%M %p'

        #     # Convert start and end strings to datetime objects
        #     start_time = datetime.datetime.strptime(start_str, format_specifier)
        #     end_time = datetime.datetime.strptime(end_str, format_specifier)
        #     print(start_time, end_time)
        # print(timeline)
        # print(src_port)

        # generate a query for multi-select fields and filter packets based on that query
        # if team_ip:
        #     # filtered packets bases on src ip addresss
        #     filtered_packets = Packets.objects.filter(source_ip__icontains=str(team_ip)).values("source_ip", "destination_ip", "timestamp", "payload")[:200]
        #     # print(filtered_packets)

        # endLimit  = 500

        current_page = request.GET.get('search_query[current_page]', 1)
        limit = int(settings.PAGE_SIZE)
        offset = (int(current_page) - 1) * limit


        # print(current_page, limit, offset)
        


        # print(team_ip)
        # filtered_packets = None
        if src_port != "" and dst_port != "":
            # raw sql query
            # filtered_packets = Packets.objects.raw(f"SELECT * FROM master_app_packets WHERE (payload LIKE '%{query}%' AND (source_ip LIKE '%{team_ip}%' OR destination_ip LIKE '%{team_ip}%') AND (source_ip LIKE '%{user_ip}%' OR destination_ip LIKE '%{user_ip}%') AND (source_ip LIKE '%{challenge_id}%' OR destination_ip LIKE '%{challenge_id}%') AND src_port = '{src_port}' AND dst_port = '{dst_port}') ORDER BY timestamp DESC LIMIT {offset}, {limit}")
            if isSameDate:

                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) 
                    & (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) 
                    & (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) 
                    & (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) 
                    & (Q(src_port=src_port ) | Q(dst_port=src_port )  )
                    & (Q(src_port=dst_por ) | Q(dst_port=dst_por ))
                    & ( Q( date__range=[startDate, endDate] )     )
                    & Q( time__range=[startTime, endTime] ) 
                    # & (Q(  ))
                    # & Q(timestamp__range=[startDate, endDate])
                    )
            else:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) 
                    & (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) 
                    & (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) 
                    & (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) 
                    & (Q(src_port=src_port ) | Q(dst_port=src_port )  )
                    & (Q(src_port=dst_por ) | Q(dst_port=dst_por ))
                    & ( Q( date__range=[startDate, endDate] )     )
                    # & Q( time__range=[startTime, endTime] ) 
                    # & (Q(  ))
                    # & Q(timestamp__range=[startDate, endDate])
                )
        elif src_port != "":
            if isSameDate:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) &
                    (Q(src_port=src_port ) | Q(dst_port=src_port )  ) 
                    & ( Q( date__range=[startDate, endDate] )     )
                    & Q( time__range=[startTime, endTime] ) 
                    
                    # & Q(timestamp__range=[startDate, endDate])
                    )
            else:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) &
                    (Q(src_port=src_port ) | Q(dst_port=src_port )  ) 
                    & ( Q( date__range=[startDate, endDate] )    )
                    
                    # & Q(timestamp__range=[startDate, endDate])
                    )
        elif dst_port != "":
            if isSameDate:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) &
                    (Q(src_port=dst_port ) | Q(dst_port=dst_port )  )
                    & ( Q( date__range=[startDate, endDate] )    )
                    & Q( time__range=[startTime, endTime] ) 
                    
                    # Q(dst_port__iexact=str(dst_port) )
                    # & Q(timestamp__range=[startDate, endDate])
                    )
            else:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) ) &
                    (Q(src_port=dst_port ) | Q(dst_port=dst_port )  )
                    & ( Q( date__range=[startDate, endDate] )    )
                    
                    # Q(dst_port__iexact=str(dst_port) )
                    # & Q(timestamp__range=[startDate, endDate])
                    )

        else:
            print("No Src and Dst Port")
            if isSameDate:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) )
                    & ( Q( date__range=[startDate, endDate] )    )
                    & Q( time__range=[startTime, endTime] ) 
                    # & Q(timestamp__range=[startDate, endDate])
                    )
            else:
                filtered_packets = Packets.objects.filter(
                    (Q(payload__icontains=str(query) ) ) &
                    (Q(source_ip__icontains=str(team_ip) ) | Q(destination_ip__icontains=str(team_ip) )  ) &
                    (Q(source_ip__icontains=str(user_ip)) | Q(destination_ip__icontains=str(user_ip) ) ) &
                    (Q(source_ip__icontains=str(challenge_id)) | Q(destination_ip__icontains=str(challenge_id) ) )
                    & ( Q( date__range=[startDate, endDate] )    )
                    # & Q( time__range=[startTime, endTime] ) 
                    # & Q(timestamp__range=[startDate, endDate])
                    )
        
        # print(filtered_packets)
        # if(team_ip):
        #     # filtered packets bases on src ip addresss
        #     filtered_packets = Packets.objects.filter(source_ip__icontains=str(team_ip)).values("source_ip", "destination_ip", "timestamp", "payload")[:200]
        #     # print(filtered_packets)

        #     filtered_packets = json.dumps(list(filtered_packets), cls=DjangoJSONEncoder)
        # if(user_ip):
        #     # filtered packets bases on src ip addresss
        #     filtered_packets = Packets.objects.filter(source_ip__icontains=str(user_ip)).values("source_ip", "destination_ip", "timestamp", "payload")[:200]
        #     # print(filtered_packets)
            
# .values("source_ip", "destination_ip", "timestamp", "payload", "src_port", "dst_port")[offset : limit+offset]
# .values("source_ip", "destination_ip", "timestamp", "payload", "src_port", "dst_port")[offset : limit+offset]
# .values("source_ip", "destination_ip", "timestamp", "payload", "src_port", "dst_port")[offset : limit+offset]
# .values("source_ip", "destination_ip", "timestamp", "payload", "src_port", "dst_port")[offset : limit+offset]
            
        count = filtered_packets.count()

        
        
        total_pages = count // limit
        if count % limit != 0:
            total_pages += 1


        # print(count, total_pages)
        filtered_packets = filtered_packets[offset : limit+offset]
        # sorted(filtered_packets)
        # print(filtered_packets)ss 
        filtered_packets = filtered_packets.values("source_ip", "destination_ip",  "payload", "src_port", "dst_port", 'time')
        
        filtered_packets = json.dumps(list(filtered_packets), cls=DjangoJSONEncoder)

        # %5Bteam_id%5D=1&query%5Buser_id%5D=&query%5Bchallenge_id%5D=&query%5Bsrc_id%5D=&query%5Bdst_id%5D=&query%5Bteam_ip%5D=192.168.1.0&query%5Buser_ip%5D=&query%5Bchallenge_ip%5D=&query%5Bsrc_port_ip%5D=&query%5Bdst_port_ip%5D=

        # print(filtered_packets)
            
            # 172.165.120.189
            # 172.165.120.189
        # 



        # current_time = datetime.now()
        # half_an_hour_ago = current_time - datetime.timedelta(minutes=30)
        # # print(current_time, half_an_hour_ago)
        # packets = Packets.objects.filter(timestamp__range=[half_an_hour_ago, current_time])
        # print(packets)
        # print(packets.count())
        # print(packets.values('timestamp'))
        # print(packets.values('timestamp').annotate(count=Count('timestamp')))
        # print(packets.values('timestamp').annotate(count=Count('timestamp')).order_by('timestamp'))
        
        return JsonResponse({'initial_packets':filtered_packets, "pagination" : {
            "current_page" : current_page,
            "limit" : limit,
            "offset" : offset,
            "count" : count,
            "total_pages" : total_pages
        }})
    except :
        traceback.print_exc()
        return JsonResponse({'initial_packets':None})



@login_required
def LiveView(request):
    template_name = "master_app/realtime.html"

    # total ip packets
    # total_packets = Packets.objects.all().count()
    # print(total_packets)



    context = {
        # "total_packets" : total_packets,
        "live_section" : True
    }
    return render(request, template_name, context)

# exempt csrf token

@csrf_exempt
def SavePacketsView(request):
    data = json.loads(request.body.decode('utf-8')).get("data", None)
    if data:
        try:
            monitoring.save_packets_api(data)
            print("API Saved Packets")
        except Exception as e:
            print("API Save Packets Exceptions")
            print(e)
            
    return JsonResponse({'initial_packets':None})


def generate_pdf_function(context_dict = {}):
  
    TEMPLATE_FILE = "master_app/report_template.html"
    # source_html = open(TEMPLATE_FILE, "r")
    # content = source_html.read()
    # source_html.close()

    template = get_template(TEMPLATE_FILE)

    # # Write your PDF generation code here
    # html = '<html><body>'
    # html += '<h1></h1>'
    # html += '<h1>Team Name: ' + team_name + '</h1>'
    # html += '<p>IP Range/Address: ' + ip_address + '</p>'
    # html += '<p>Report Date: ' + report_date + '</p>'
    # html += '<hr />'
    # html += '<h3>Total Packets: ' + str(total_packets) + '</h3>'
    # html += '</body></html>'
    # result = pisa.CreatePDF(html, dest=BytesIO())
    html  = template.render(context_dict)
    result = BytesIO()
    result = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")))
    return result


@login_required
def GenerateReport(request):
    if request.method == 'POST':
        data_post = json.loads(request.body.decode('utf-8'))
        print(data_post)
        # total_src_ports = Packets.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count')
        # count total distinct src ports
        #
        #

        # total distinct src ports
        total_src_ports = Packets.objects.values('src_port').distinct().count()

        # total distinct dst ports
        total_dst_ports = Packets.objects.values('dst_port').distinct().count()

        # list of distinct src ports with counter
        src_ports_list = Packets.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count')


        # list of distinct src ports with counter
        dst_ports_list = Packets.objects.values('dst_port').annotate(count=Count('dst_port')).order_by('-count')

        # print(src_ports_list)

        # print

        # print(total_src_ports)
        data = {
            "team_name" : data_post["team_name"],
            "report_time" : str(datetime.datetime.now()),
            "ip_address" : data_post["ip_address"],
            "total_packets" : str(Packets.objects.all().count()),
            "total_src_ports" : total_src_ports,
            "total_dst_ports" : total_dst_ports,
            "src_ports_list" : src_ports_list,
            "dst_ports_list" : dst_ports_list,
        }
        result = generate_pdf_function(data )
        if result.err:
            return HttpResponse('Error generating PDF: %s' % result.err)
        response = HttpResponse(content_type='application/pdf')
        response.write(result.dest.getvalue())
        return response
    template_name = "master_app/report.html"
    context = {

    }
    return render(request, template_name, context)




def download_pcap_file(request):


    # print(request.GET)


    fielname = request.GET.get("filename", None)
    fielname = fielname.replace(".", "_") 

    filename = os.path.join(settings.PCAP_DIR , fielname + ".pcap") 

    # print(filename)
    # print(os.path.exists(filename))

    # check a file exists or not
    if not os.path.exists(filename):
        return JsonResponse({"status" : "error", "message" : "File Not Found"})
    else:
        return JsonResponse({"status" : "ok" , "name" : fielname})


    # 
    # print(fielname, settings.PCAP_DIR)


    # print(setti)

    # return JsonResponse({'initial_packets':None, "status" : "success"})

    # if request.method == 'POST':
    #     data_post = json.loads(request.body.decode('utf-8'))
    #     print(data_post)
    #     document_id = data_post["document_id"]
    #     try:
    #         document = Document.objects.get(id=document_id)
    #         # print(document.document.path)
    #         with open(document.document.path, 'rb') as fh:
    #             response = HttpResponse(fh.read(), content_type="application/vnd.tcpdump.pcap")
    #             # response['Content-Disposition'] = 'inline; filename=' + os.path.basename(document.document.path)
    #             return response
    #     except Exception as e:
    #         print(e)
    #         return HttpResponse('Error generating PDF: %s' % e)
    # return HttpResponse('Error generating PDF: %s' % "No Post Request")
        


@login_required
def pcap_files_list(request):
    
    temlpate_name = "master_app/pcap_files_list.html"
    # files_list = os.listdir(settings.PCAP_DIR)
    # print(files_list)

    # list of pcap files with their size and download link
    # size should be in a good format
    # download link should be a url that can be used to download a file
    # format size according to kb, mb, gb, tb
    #
    #
    # format file zie in kbs mbs    
    # print(files_list)



    # files_list = [{
    #     "name" : file,
    #     "size" : os.path.getsize(os.path.join(settings.PCAP_DIR, file)),
    #     "download_link" : "/media/pcap_files/" + file
    # } for file in files_list]
    # print(files_list)
    # 
    context = {
        # "files_list" : files_list
        "files_list" : True
    }
    return render(request, temlpate_name, context)



# @login_required
def pcap_files_list_view_json(request):
    try:
        files_list = os.listdir(settings.PCAP_DIR)
        # Exclude "dummy.pcap" from the files_list
        # files_list = [file for file in files_list if file != "dummy.pcap"]
        files_list = [file for file in files_list if (file != "dummy.pcap" and not file.endswith(".txt") and file != "tmp")  ]
        
        
        # print(files_list)
        # 
        files_list = [{
            "name" : file.replace(".pcap", "").replace("_", "."),
            "size" : os.path.getsize(os.path.join(settings.PCAP_DIR, file)),
            "download_link" : "/media/pcap_files/" + file,
            "details" : "/files/analyze/" + file.replace(".pcap", "")
        } for file in files_list ]
        # print(files_list)
        files_list = sorted(files_list, key = lambda i: i['size'], reverse=True)
        files_list = json.dumps(list(files_list), cls=DjangoJSONEncoder)
        return JsonResponse({'files_list':files_list})
    except :
        traceback.print_exc()
        files_list = None
        return JsonResponse({'files_list':files_list})
    

# User Executed Commands Views
def commands_view(request):
    template_name = "master_app/commands.html"
    context = {
        "commands_section" : True
    }
    return render(request, template_name, context)



# select those packets where dst post is src port and dst ip is src ip
# and payload contains cat

# # Example usage
# my_list = [1, 2, 3, 4, 5]
# for item in read_list(my_list):
#     print(item)


# User Executed Commands Json view

# 

def commands_view_json(request):
    # most executed and command linux commands
    try:

        # Get First 500 Packets
        src_ip_address = request.GET.get("query[src_ip_address]", "192.168.14.161")
        dst_ip_address = request.GET.get("query[dst_ip_address]", "35.232.111.17")
        src_port = request.GET.get("query[src_port]", "80")
        dst_port = request.GET.get("query[dst_port]", "32908")
        # print(src_ip_address, dst_ip_address, src_port, dst_port)
        pkts = Packets.objects.filter(
            (Q(source_ip__icontains=str(src_ip_address) ) | Q(destination_ip__icontains=str(src_ip_address) )  ) &
            
            (Q(src_port__iexact=str(src_port) ) | Q(dst_port__iexact=str(src_port) ) ) &
            (Q(src_port__iexact=str(dst_port) ) | Q(dst_port__iexact=str(dst_port) ) )
        ).order_by("timestamp")[:500]
        
        # pkts = Packets.objects.all()[:500]

        # data = []
        data = [pkt for pkt in read_list(pkts)]
        # print(data)   

        


        # sorted(data)

        # 

        # print(data)

        # for pkt in read_list(pkts):
        #     print(pkt)



        # filtered_packets = Packets.objects.filter(
        #     ( Q(payload__icontains=("cat") ) | Q(attack_name__icontains=("cat") ) ) 
        # )

        # for i in read_list(filtered_packets):
        #     for j in read_list(filtered_packets):
        #         if i.source_ip == j.destination_ip and i.destination_ip == j.source_ip and i.src_port == j.dst_port and i.dst_port == j.src_port:
        #             filtered_packets = filtered_packets.exclude(id=j.id)

        # print(filtered_packets.count())
        # print(filtered_packets[0])
        # print(filtered_packets[0].payload, filtered_packets[0]., )

        # filtered_packets = Packets.objects.filter(
        #     ( Q(payload__icontains=("cat") ) | Q(attack_name__icontains=("cat") ) ) 
        # )

        



        
        # print(filtered_packets.count())
        commands = pkts.values("payload")


        # commands = commands.order_by("timestamp")
        commands = json.dumps(list(commands), cls=DjangoJSONEncoder)
        # print(commands)
        return JsonResponse({'commands':commands})
    except :
        traceback.print_exc()
        commands = None
        return JsonResponse({'commands':commands})





def is_human_readable(s):
    # Define a set of printable ASCII characters
    printable_ascii = set(range(32, 127))
    

    # Check if all characters in the string are printable ASCII
    return all(ord(char) in printable_ascii for char in s)





# function isHumanReadable(str) {
#   // Define a regular expression to match printable ASCII characters
#   const printableRegex = /^[\x20-\x7E]*$/;

#   // Test if the string contains only printable ASCII characters
#   return printableRegex.test(str);
# }M-SEARCH

# M-SEARCH


from master_app.p0f_files import *
from master_app.read_mac_address import *


def analyze_pcap_file(request, filename):
    template_name = "master_app/analyze_pcap_file.html"
    try:
        if filename is None:
            # message.error(request, "File Not Found")
            return redirect("pcap_files_list")
        
        # # enter the directory like this:
        # # with cd("~/"):
        # # we are in ~/Library
        #     # subprocess.call("ls")
        # pcap_files_dir = settings.PCAP_DIR
        # # print(str(pcap_files_dir))
        # # absolute_path = pcap_files_dir.abspath()
        # # print(absolute_path)
        # # print(str(pcap_files_dir))
        # # subprocess.call("../../pcap_files/", shell=True)
        # pcap_name = filename
        # fn = settings.PCAP_DIR / f"{pcap_name}.pcap"

        # # print(fn)

        # dst = settings.PCAP_DIR / "tmp" / f"{pcap_name}.pcap"

        # shutil.copyfile(fn, dst)

        # output_filepath = settings.PCAP_DIR / "tmp" / f"output.txt"


        # # fn =  pcap_files_dir.join("20_250_58_93" ,".pcap")
        # # p0f -r 20_250_58_93.pcap -o output.txt
        # command = ["p0f" , "-r" , dst , "-o" , f"{output_filepath}"]
        
        # # print(command)
        # subprocess.run(command, cwd=f"{pcap_files_dir}")


        # # print("Output is generated")

        
        # os_list = get_os(output_filepath)

        # os.remove(dst)

        # # print(os_list)

        # os_list = json.dumps(os_list, cls=DjangoJSONEncoder)

        # # print(os_list)


        context = {
            # "os_list" : os_list
            "filename" : filename

        }
        return render(request, template_name, context)
    except :
        traceback.print_exc()
        return redirect("pcap_files_list")




def analyze_pcap_file_os_json(request, filename):
    try:
        if filename is None:
            return JsonResponse({"status" : "error", "message" : "File Not Found", os_list : None})
        pcap_files_dir = settings.PCAP_DIR
        pcap_name = filename
        fn = settings.PCAP_DIR / f"{pcap_name}.pcap"
        dst = settings.PCAP_DIR / "tmp" / f"{pcap_name}.pcap"
        shutil.copyfile(fn, dst)
        output_filepath = settings.PCAP_DIR / "tmp" / f"output.txt"
        command = ["p0f" , "-r" , dst , "-o" , f"{output_filepath}"]
        subprocess.run(command, cwd=f"{pcap_files_dir}")
        ip_address = filename.replace("_", ".")
        os_list = get_os(output_filepath, ip_address)
        # print(os_list)
        # os_list = {"ip_address" : os_list[0]}
        # remove dst pcap file, txt file
        # os.remove(dst)
        # os.remove(output_filepath)
        os_list = json.dumps(os_list, cls=DjangoJSONEncoder)
        return JsonResponse({"os_list" : os_list})
    except :
        traceback.print_exc()
        return JsonResponse({"status" : "error", "message" : "File Not Found", os_list : None})


# ? Pcap MAC Addresses (src + dst)
@login_required
def analyze_pcap_file_mac_json(request, filename):
    
    try:
        if filename is None:
            # return redirect("pcap_files_list")
            return JsonResponse({ "mac_list" : None})

        # print("MAC Addresses")
        pcap_files_dir = settings.PCAP_DIR
        pcap_name = filename
        fn = settings.PCAP_DIR / f"{pcap_name}.pcap"
        dst = settings.PCAP_DIR / "tmp" / f"{pcap_name}.pcap"
        shutil.copyfile(fn, dst)
        output_filepath = settings.PCAP_DIR / "tmp" / f"output_mac.txt"
        # -E header=y -E separator=, -E quote=d -E occurrence=f 
        # tshark -r captured_packets.pcap -T fields -e eth.src_resolved -e ip.src -e eth.dst_resolved -e ip.dst | sort | uniq -c > output.txt
        myoutput = open(output_filepath, 'w')
        command = ["tshark" , "-r" , dst , "-T" , "fields" , "-e", "eth.src", "-e" , "eth.src.oui_resolved", "-e", "ip.src", "-e", "eth.dst",  "-e",  "eth.dst.oui_resolved", "-e" , "ip.dst" ,   "-E", "separator=|", "-E", "occurrence=f"]

        # print(command)
        subprocess.run(command, cwd=f"{pcap_files_dir}", stdout=myoutput)


        # read mac addresses
        ip_address = filename.replace("_", ".")

        mac_list = read_mac_address(myoutput,ip_address)


        # print(mac_list)

        # print(output_filepath)

        # os_list = get_os(output_filepath)
        # os.remove(dst)
        mac_list = json.dumps(mac_list, cls=DjangoJSONEncoder)
        # print("-"*70)
        # print("Analyze Mac")
        # print("-"*70)
        return JsonResponse({"mac_list" : mac_list})
    except :
        traceback.print_exc()
        return JsonResponse({ "mac_list" : None})



# ? Pcap Common IP Addresses
# filemane -> pcap fileman
@login_required
def common_ip(request, filename):
    try:
        if filename is None:
            return JsonResponse({ "common_ip" : None})
        else:
            print("Common Src and Dst IP Addresses")
            pcap_files_dir = settings.PCAP_DIR
            src_filepath = settings.PCAP_DIR / "tmp" / f"{filename}.pcap"
            output_filepath = settings.PCAP_DIR / "tmp" / f"output_common.txt"
            myoutput = open(output_filepath, 'w')
            command = ["tshark" , "-r" , src_filepath ,"-2", "-Tfields", "-R", "ip", "-e", "ip.src", "-e", "ip.dst", "-E","separator=|","-E", "occurrence=f"]
            subprocess.run(command, cwd=f"{pcap_files_dir}", stdout=myoutput)
            # myoutput.close()
            ip_address = filename.replace("_", ".")
            # print(filename)
            common_ip = get_common_ip_addresses(myoutput, ip_address)
            # print(common_ip)
            return JsonResponse({ "common_ip" : common_ip})
    except :
        traceback.print_exc()
        return JsonResponse({ "common_ip" : None})



# ? Pcap User Agents
@login_required
def user_agents(request, filename):
    try:
        if filename is None:
            return JsonResponse({ "user_agents" : None})
        else:
            print("User Agents")
            pcap_files_dir = settings.PCAP_DIR
            src_filepath = settings.PCAP_DIR / "tmp" / f"{filename}.pcap"
            # pcap_files_dir = settings.PCAP_DIR
            pcap_name = filename
            fn = settings.PCAP_DIR / f"{pcap_name}.pcap"
            dst = settings.PCAP_DIR / "tmp" / f"{pcap_name}.pcap"
            shutil.copyfile(fn, dst)
            output_filepath = settings.PCAP_DIR / "tmp" / f"output_user_agents.txt"
            myoutput = open(output_filepath, 'w')
            # tshark -r example.pcap -Y http.request -T fields -e http.host -e http.user_agent | sort | uniq -c | sort -n
            # tshark -R 'http contains "User-Agent:"' -2T fields -e http.user_agent -r packet_capture.pcap
            command = ["tshark" , "-R", 'http contains "User-Agent:"', "-2T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.user_agent", "-Y", 'http.user_agent matches "(sqlmap|nmap|dirb)"' , "-E","separator=|","-E", "occurrence=f", "-r" , src_filepath ]
            # tshark -R 'http contains "User-Agent:"' -2T fields -e http.user_agent -r packet_capture.pcap
            # ,"-Y", "http.request", "-T" , "fields", "-e", "http.host", "-e", "http.user_agent", "-E","separator=|","-E", "occurrence=f"
            subprocess.run(command, cwd=f"{pcap_files_dir}", stdout=myoutput)
            # myoutput.close()
            ip_address = filename.replace("_", ".")
            # # print(filename)
            user_agents = get_user_agents(myoutput, ip_address)
            # print(user_agents)
            # print(common_ip)
            # user_agents = None
            # user_agents = json.dumps(list(user_agents), cls=DjangoJSONEncoder)

            return JsonResponse({ "user_agents" : user_agents})
    except :
        traceback.print_exc()
        return JsonResponse({ "user_agents" : None})





@login_required
def logs_view(request):
    template_name = "master_app/logs.html"
    context = {
        "logs_section" : True
    }
    return render(request, template_name, context)


@login_required
def logs_view_json(request):
    try:
        initial_packets = External.objects.filter().order_by('source_ip').values('id', 'source_ip', 'destination_ip', 'payload', 'date', 'time', 'src_port', 'dst_port', 'date', 'time', 'attack_name', 'severity')[:500]
        # print(initial_packets)
        initial_packets = json.dumps(list(initial_packets), cls=DjangoJSONEncoder)
        return JsonResponse({'initial_packets':initial_packets})
    except :
        traceback.print_exc()
        initial_packets = None
        
        return JsonResponse({'initial_packets':initial_packets})
        


# ? Log Analysis View
@login_required
def logs_analysis_view(request):
    template_name = "master_app/logs_analysis.html"
    # output = subprocess.check_output("ls -l /var/log/", shell=True)
    # print(output.decode("utf-8"))
    # print(pathlib.Path(__file__).parent.resolve())

    data_filepath = os.path.join(pathlib.Path(__file__).parent.resolve(), "data.json")
    # print(data_filepath)
    
    data = read_json(data_filepath)
    # print(data)


    context = {
        "logs_analysis_section" : True,
        "data"  : data
    }
    return render(request, template_name, context)

# ? Log Analysis Team View
@login_required
def log_analysis_team_view(request, team_id):
    template_name = "master_app/logs_analysis_detail.html"

    if team_id is None:
        return redirect("logs_analysis_view")

    data = read_json_key(os.path.join(pathlib.Path(__file__).parent.resolve(), "data.json"), team_id)
    # print(data)

    if data is None:
        return redirect("logs_analysis_view")

    # print(data)
    context = {
        "logs_analysis_section" : True,
        "data"  : data
    }
    return render(request, template_name, context)