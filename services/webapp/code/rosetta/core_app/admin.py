from django.contrib import admin

from .models import Profile, LoginToken, Task, Container, Computing, Storage, KeyPair, Page

admin.site.register(Profile)
admin.site.register(LoginToken)
admin.site.register(Task)
admin.site.register(Container)
admin.site.register(Computing)
admin.site.register(Storage)
admin.site.register(KeyPair)
admin.site.register(Page)
