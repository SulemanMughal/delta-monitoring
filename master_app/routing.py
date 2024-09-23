# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.security.websocket import AllowedHostsOriginValidator
# from channels.auth import AuthMiddlewareStack

# from django.urls import path


from master_app.consumers import PracticeConsumer

# # application = ProtocolTypeRouter({
# #     'websocket':AllowedHostsOriginValidator(
# #         AuthMiddlewareStack(
# #             URLRouter([
            
# #             path('whole1/',PracticeConsumer.as_asgi()),
# #             ])
# #         )
# #     )
# # })

# websocket_urlpatterns=[
#                     path('ws/whole1/',PrawzcticeConsumer.as_asgi()),
#                 ]

# application = ProtocolTypeRouter( 
#     {
#         "websocket": AuthMiddlewareStack(
#             URLRouter(
#                websocket_urlpatterns
#             )
#         ),
#     }
# )

from django.urls import re_path

# from . import consumers

websocket_urlpatterns = [
    re_path(r"ws/whole1/$", PracticeConsumer.as_asgi()),
]