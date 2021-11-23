from django.contrib import admin

from .models import Profile, LoginToken, Task, Container, Computing, Storage, KeyPair, Page

# Define a extra "ModelAdmin" for the Container model to allow "save as" to easily duplicate containers
class ContainerForAdmin(admin.ModelAdmin):
    save_as = True

admin.site.register(Profile)
admin.site.register(LoginToken)
admin.site.register(Task)
admin.site.register(Container, ContainerForAdmin)
admin.site.register(Computing)
admin.site.register(Storage)
admin.site.register(KeyPair)
admin.site.register(Page)
