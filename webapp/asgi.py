# """
# ASGI config for webapp project.

# It exposes the ASGI callable as a module-level variable named ``application``.

# For more information on this file, see
# https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
# """

# import os


# from django.core.asgi import get_asgi_application

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webapp.settings')

# application = get_asgi_application()

# import os

# from channels.routing import ProtocolTypeRouter
# from django.core.asgi import get_asgi_application

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webapp.settings')

# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),
# })

# import os

# from channels.routing import ProtocolTypeRouter
# from django.core.asgi import get_asgi_application

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webapp.settings')
# # Initialize Django ASGI application early to ensure the AppRegistry
# # is populated before importing code that may import ORM models.
# django_asgi_app = get_asgi_application()

# application = ProtocolTypeRouter({
#     "http": django_asgi_app,
#     # Just HTTP for now. (We can add other protocols later.)
# })

import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "webapp.settings")
django.setup()


from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

from master_app.routing import websocket_urlpatterns

django_asgi_app = get_asgi_application()

import master_app.routing

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": URLRouter(websocket_urlpatterns),
    }
)


# import os

# import django
# from channels.http import AsgiHandler
# from channels.routing import ProtocolTypeRouter,get_default_application


# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webapp.settings')
# # django.setup()


# application=get_asgi_application()
