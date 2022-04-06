"""rosetta URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

import os
import django
from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin
from django.urls import include, path
from django.conf.urls import url
import logging

logger = logging.getLogger(__name__)

# Base App
from rosetta.core_app import api as core_app_api
from rosetta.core_app import views as core_app_views

# REST Framework & Swagger
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from rest_framework_swagger.views import get_swagger_view

core_app_api_router = routers.DefaultRouter()
core_app_api_router.register(r'users', core_app_api.UserViewSet)

urlpatterns = [
               
    # Pages
    url(r'^$', core_app_views.entrypoint),
    path('main/', core_app_views.main_view),
    path('login/', core_app_views.login_view),
    path('logout/', core_app_views.logout_view),
    url(r'^register/$', core_app_views.register_view),
    url(r'^pages/(?P<page_id>\w{0,36})/$', core_app_views.page_view),

    
    # Software    
    url(r'^software/$', core_app_views.software),
    url(r'^add_software/$', core_app_views.add_software),    
    url(r'^import_repository/$', core_app_views.import_repository),    
    
    #Computing
    url(r'^computing/$', core_app_views.computing),
    
    # Storage
    url(r'^storage/$', core_app_views.storage),
    
    # Tasks
    url(r'^tasks/$', core_app_views.tasks),
    url(r'^new_task/$', core_app_views.new_task),
    url(r'^task_log/$', core_app_views.task_log),
    url(r'^task_connect/$', core_app_views.task_connect),
    
    # Sharable and direct connection links for tasks
    url(r'^direct_connect/(?P<uuid>[0-9a-f-]+)/$', core_app_views.direct_connection_handler),
    url(r'^t/(?P<short_uuid>\w{0,36})/$', core_app_views.sharable_link_handler),

    # Account
    url(r'^account/$', core_app_views.account),
    url(r'^add_profile_conf/$', core_app_views.add_profile_conf),

    # OpenID Connect Auth
    path('oidc/', include('mozilla_django_oidc.urls')),

    # Admin and API docs (Swagger)
    path('admin/', admin.site.urls),
    path('api/v1/doc/', get_swagger_view(title="Swagger Documentation")),
    
    # APIs
    path('api/v1/base/login/', core_app_api.login_api.as_view(), name='login_api'),
    path('api/v1/base/logout/', core_app_api.logout_api.as_view(), name='logout_api'),
    path('api/v1/base/agent/', core_app_api.agent_api.as_view(), name='agent_api'),
    path('api/v1/filemanager/', core_app_api.FileManagerAPI.as_view(), name='filemanager_api'),
    path('api/v1/import_repository/', core_app_api.ImportRepositoryAPI.as_view(), name='import_repository_api'),

    # Binder compatibility
    path('v2/git/<path:repository>', core_app_views.new_binder_task),


]


#============================
#  Serve static if required
#============================

# Get admin files location
admin_files_path = '/'.join(django.__file__.split('/')[0:-1]) + '/contrib/admin/static/admin'
 
if not settings.DEBUG:

    # Admin files
    urlpatterns.append(url(r'^static/admin/(?P<path>.*)$', django.views.static.serve, {'document_root': admin_files_path} ))

    # Rosetta Core app files
    document_root = 'rosetta/core_app/static'
     
    if os.path.isdir(document_root):
        logger.info('Serving static files for app "core_app" from document root "{}"'.format(document_root))
        # Static
        urlpatterns.append(url(r'^static/(?P<path>.*)$', django.views.static.serve, {'document_root': document_root} ))
    else:
        logger.warning('Not static files to serve?!')
else:
    logger.info('Not serving static files at all as DEBUG=True (Django will do it automatically)')


