from django.urls import path

# from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index' ),
    path('login', views.UserLoginView, name="user_login"),


    # ? Monitoring Page
    path("live", views.LiveView, name="live_url"),

    path('logout', views.UserLogoutView, name="user_logout"),
    
    
    # ? Dashboard Page
    path('dashboard', views.Dashboard, name="dashboard_url"),


    path("upload", views.document_upload_view, name="document_upload_url"),
    path("files/details/<document_id>", views.document_details, name="document_details_url"),
    path("files/list", views.document_list_view, name="document_list_url"),
    path("files/details/<document_id>/json", views.document_details_json, name="document_details_json_url"),
    path("files/list/json", views.document_list_json, name="document_list_json_url"),
    
    path("save_packets", views.SavePacketsView, name="save_packets"),

    # Reports ULR
    path("report", views.GenerateReport, name="generate_report_url"),
    # path("generate_pdf", views.generate_pdf, name="generate_pdf_url"),

    # ? Search Page
    path("search", views.search, name="search_url"),
    path("search/json", views.saerch_json, name="search_json_url"),
    path("search/chart/json", views.search_chart_data, name="search_chart_json_url"), 


    # fetch download link to pcap file
    path("download/", views.download_pcap_file, name="download_pcap_file_url"),

    # ? Pcap Files List Page
    path("files/list/", views.pcap_files_list, name="pcap_files_list"),


    # -----------------------------------------
    # ? Pcap Files List Page
    path("files/analyze/<filename>", views.analyze_pcap_file, name="analyze_pcap_file_url"),

    # ? Json analyze pcap files (os details)
    path("files/analyze/<filename>/os", views.analyze_pcap_file_os_json, name="analyze_pcap_file_os_json_url"),

    # ? fetch mac addresses details
    path("files/analyze/<filename>/mac", views.analyze_pcap_file_mac_json, name="analyze_pcap_file_mac_json_url"),

    # ? fetch common src and dst ip addresses
    path("files/analyze/<filename>/ip", views.common_ip, name="common_ip_url"),


    # ? fetch host user agents
    path("files/analyze/<filename>/user_agents", views.user_agents, name="user_agents_url"),

    # -----------------------------------------

    path("files/list/pcap/json", views.pcap_files_list_view_json, name="pcap_files_list_json"),

    # ? Commands executed by user 
    path("commands/", views.commands_view, name="commands_url"),
    path("commands/json/", views.commands_view_json, name="commands_json_url"),

    # ? Logs Views Page
    path("logs", views.logs_view, name="logs_view_url"),
    path("logs/json", views.logs_view_json, name="logs_view_json_url"),


    # ? Log Analysis Page
    path("logs/analyze", views.logs_analysis_view, name="logs_analysis_url"),


    # ? Log Analysis Details Page
    path("logs/analyze/<team_id>", views.log_analysis_team_view, name="log_analysis_team_url"),


]

