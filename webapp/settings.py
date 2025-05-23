"""
Django settings for webapp project.

Generated by 'django-admin startproject' using Django 5.0.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path

from decouple import config, Csv
# from decouple import 

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())


# if DEBUG:
#     INTERNAL_IPS = ["127.0.0.1"]  # <-- Updated!

# Application definition

INSTALLED_APPS = [
    "daphne",
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'master_app',
    'channels',
    # "debug_toolbar",  # <-- Updated!


]

MIDDLEWARE = [
    # "debug_toolbar.middleware.DebugToolbarMiddleware",  # <-- Updated!
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # "django.middleware.cache.UpdateCacheMiddleware",
    'django.middleware.common.CommonMiddleware',
    # "django.middleware.cache.FetchFromCacheMiddleware",
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'webapp.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'master_app/templates/master_app',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'webapp.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases


# Get the environment: 'development' or 'production'
ENVIRONMENT = config('ENVIRONMENT', default='development')

if ENVIRONMENT == 'development':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': config('DB_NAME'),
        }
    }
elif ENVIRONMENT == 'production':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': config('DB_NAME'),
            'USER': config('DB_USER'),
            'PASSWORD': config('DB_PASSWORD'),
            'HOST': config('DB_HOST'),
            'PORT': config('DB_PORT'),
        }
    }
else:
    raise ValueError("Unknown environment setting: " + ENVIRONMENT)



# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Karachi'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

STATIC_ROOT= BASE_DIR / 'static'
STATICFILES_DIRS=[
]

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

MEDIA_URL = '/media/'
MEDIA_ROOT= BASE_DIR.parent / 'media'

from django.urls import reverse_lazy

LOGIN_REDIRECT_URL = reverse_lazy('dashboard_url')
LOGIN_URL = reverse_lazy('user_login')
LOGOUT_URL = reverse_lazy('user_logout')



# Target Port
TARGET_PORT=config('TARGET_PORT')


# Websocket configurations
# ASGI_APPLICATION = 'webapp.routing.application'
# ASGI_APPLICATION = "webapp.routing.application"
ASGI_APPLICATION = "webapp.asgi.application"



# CHANNEL_LAYERS = {
#     'default': {
#         'BACKEND': "channels.layers.InMemoryChannelLayer"
#     }
# }


if config("CHANNEL_LAYERS") == "MEMORY_CHANNEL_LAYERS":
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': "channels.layers.InMemoryChannelLayer"
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [(config("REDIS_CACHE_SERVER_HOST"), config("REDIS_CACHE_SERVER_PORT"))],
            },
        },
    }



# CACHES = {
#     "default": {
#         'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
#         "LOCATION": "127.0.0.1:11211",
#     }
# }

if config("ENABLE_CACHE", cast=bool):
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": config("REDIS_CACHE_SERVER"),
            "KEY_PREFIX": "imdb",
            "TIMEOUT": config("CACHE_TIMEOUT"),
        }
    }


# SERVER NETWORK INTERFACE FOR REAL TIME MONITORING
NETWORK_INTERFACE_LABEL=config('NETWORK_INTERFACE_LABEL')




# PCAP_DIR = BASE_DIR.parent / 'media' / 'pcap_files'
PCAP_DIR = BASE_DIR.parent / 'media' / 'documents'

# Pagination Parameters
PAGE_SIZE=config('PAGE_SIZE', cast=int)
