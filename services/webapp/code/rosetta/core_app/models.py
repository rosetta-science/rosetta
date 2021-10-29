import uuid
import json
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from .utils import os_shell, color_map, hash_string_to_int
from .exceptions import ConsistencyException

if 'sqlite' in settings.DATABASES['default']['ENGINE']:
    from .fields import JSONField
else:
    from django.contrib.postgres.fields import JSONField

class ConfigurationError(Exception):
    pass

class ConsistencyError(Exception):
    pass


# Setup logging
import logging
logger = logging.getLogger(__name__)


# Task statuses
class TaskStatuses(object):
    created = 'created'
    sumbitted = 'sumbitted' # TODO: fix me!
    running = 'running'
    stopped = 'stopped'
    exited = 'exited'

# All char model attributes are based on a 36 chars field. This is for making it easy to switch
# using an UUID pointing to some other model instead of the value in future, should this be necessary.

#=========================
#  Profile 
#=========================

class Profile(models.Model):

    uuid      = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user      = models.OneToOneField(User, on_delete=models.CASCADE)
    timezone  = models.CharField('User Timezone', max_length=36, default='UTC')
    authtoken = models.CharField('User auth token', max_length=36, blank=True, null=True)


    def save(self, *args, **kwargs):
        if not self.authtoken:
            self.authtoken = str(uuid.uuid4())
        super(Profile, self).save(*args, **kwargs)


    def __unicode__(self):
        return str('Profile of user "{}"'.format(self.user.username))



#=========================
#  Login Token 
#=========================

class LoginToken(models.Model):

    uuid  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user  = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField('Login token', max_length=36)



#=========================
#  Containers
#=========================
class Container(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE, blank=True, null=True)  
    # If a container has no user, it will be available to anyone. Can be created, edited and deleted only by admins.

    # Generic attributes
    name        = models.CharField('Container Name', max_length=255, blank=False, null=False)
    description = models.TextField('Container description', blank=True, null=True)
    
    # Registry-related attributes
    registry = models.CharField('Container registry', max_length=255, blank=False, null=False)
    image    = models.CharField('Container image', max_length=255, blank=False, null=False)
    tag      = models.CharField('Container image', max_length=255, blank=False, null=False, default='latest')

    # Platform-related
    arch = models.CharField('Container architecture', max_length=36, blank=False, null=False, default='x86_64')
    os   = models.CharField('Container operating system', max_length=36, blank=False, null=False, default='linux')
    
    # TODO: do we want more control with respect to kernel, CPUs, instruction sets? 
    # requires = i.e. kernel > 3, intel, AVX2
    
    # Port, protocol and transport for the container interface
    interface_port = models.IntegerField('Container interface port', blank=True, null=True) 
    interface_protocol = models.CharField('Container interface protocol', max_length=36, blank=True, null=True)
    interface_transport = models.CharField('Container interface protocol', max_length=36, blank=True, null=True)

    # Capabilities
    supports_custom_interface_port = models.BooleanField('Does the container support setting a custom interface port?', default=False) # BASE_PORT
    supports_interface_auth = models.BooleanField('Does the container interface support authentication?', default=False) # AUTH_USER / AUTH_PASS

    class Meta:
        ordering = ['name']

    def __str__(self):
        return str('Container "{}" with image "{}" and tag "{}" of user "{}" on registry "{}" '.format(self.name, self.image, self.tag, self.user, self.registry))

    #@property
    #def id(self):
    #    return str(self.uuid).split('-')[0]

    @ property
    def color(self):
        string_int_hash = hash_string_to_int(self.registry + self.image + self.tag)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]


#=========================
#  Computing resources
#=========================

class Computing(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE, blank=True, null=True)
    # If a compute resource has no user, it will be available to anyone. Can be created, edited and deleted only by admins.
    
    name        = models.CharField('Computing Name', max_length=255, blank=False, null=False)
    description = models.TextField('Container description', blank=True, null=True)

    # Standalone / sluster
    type = models.CharField('Computing Type', max_length=255, blank=False, null=False)

    requires_sys_conf  = models.BooleanField(default=False)
    requires_user_conf = models.BooleanField(default=False)
    requires_user_keys = models.BooleanField(default=False)

    # Interfce and interaction definition
    access_mode = models.CharField('Computing resource access (control) mode', max_length=36, blank=False, null=False)
    auth_mode   = models.CharField('Computing resource authentication mode', max_length=36, blank=False, null=False)
    wms         = models.CharField('Computing resource WMS', max_length=36, blank=True, null=True)
    
    # Supported container runtimes
    container_runtimes = models.CharField('Computing resource container runtimes', max_length=256, blank=False, null=False) 

    class Meta:
        ordering = ['name']

    def __str__(self):
        if self.user:
            return str('Computing "{}" of user "{}"'.format(self.name, self.user))
        else:
            return str('Computing "{}"'.format(self.name))

    @property
    def id(self):
        return str(self.uuid).split('-')[0]

    @property
    def color(self):
        string_int_hash = hash_string_to_int(self.name)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]


    #=======================
    # Computing manager
    #=======================
    
    @property
    def manager(self):
        from . import computing_managers
        
        # Instantiate the computing manager based on type (if not already done)
        try:
            return self._manager
        except AttributeError:
            if self.type == 'cluster' and self.access_mode == 'ssh+cli' and self.access_mode == 'user_keys' and self.wms == 'slurm':
                self._manager = computing_managers.SlurmSSHClusterComputingManager(self)
            elif self.type == 'standalone' and self.access_mode == 'ssh+cli' and self.access_mode == 'user_keys' and self.wms is None:
                self._manager = computing_managers.SSHSingleNodeComputingManager(self)
            elif self.type == 'standalone' and self.access_mode == 'internal' and self.access_mode == 'internal' and self.wms is None:
                self._manager = computing_managers.InternalSingleNodeComputingManager(self)
            else:
                raise ConsistencyException('Don\'t know how to instantiate a computing manager for computing resource of type "{}", access mode "{}" and WMS "{}"'.format(self.type, self.access_mode, self.wms))
            return self._manager
    
    
    #=======================
    # Sys & user conf
    #=======================

    def attach_user_conf(self, user):
        if self.user and self.user != user:
            raise Exception('Cannot attach a conf data for another user (my user="{}", another user="{}"'.format(self.user, user)) 
        try:
            self._user_conf_data = ComputingUserConf.objects.get(computing=self, user=user).data
        except ComputingUserConf.DoesNotExist:
            self._user_conf_data = None

    @property
    def sys_conf(self):
        return self.related_sys_conf.get().data

    @property
    def user_conf(self):
        try:
            return self._user_conf_data
        except AttributeError:
            raise ConsistencyException('User conf has to been attached, cannot proceed.')

    @property    
    def sys_conf_as_json(self):
        return json.dumps(self.sys_conf)
    
    @property    
    def user_conf_as_json(self):
        return json.dumps(self.user_conf)

    @property
    def conf(self):
    
        if not self.requires_user_conf:  
            conf_tmp = self.sys_conf
        else:
            try:
                # Copy the conf or the original user conf will be affected by the overwrite below
                conf_tmp = {key:value for key, value in self._user_conf_data.items()}
            except AttributeError:
                raise ConsistencyException('User conf has not been attached, cannot proceed.')
            
            # Now add (overwrite) with the sys conf
            sys_conf = self.sys_conf
            for key in sys_conf:
                conf_tmp[key] = sys_conf[key]

        return conf_tmp


            
class ComputingSysConf(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    computing = models.ForeignKey(Computing, related_name='related_sys_conf', on_delete=models.CASCADE)
    data = JSONField(blank=True, null=True)


    @property
    def id(self):
        return str(self.uuid).split('-')[0]


    def __str__(self):
        return 'Computing sys conf for {} with id "{}"'.format(self.computing, self.id)



class ComputingUserConf(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE, null=True)
    computing = models.ForeignKey(Computing, related_name='related_user_conf', on_delete=models.CASCADE)
    data = JSONField(blank=True, null=True)

    @property
    def id(self):
        return str(self.uuid).split('-')[0]

    def __str__(self):
        return 'Computing user conf for {} with id "{}" of user "{}"'.format(self.computing, self.id, self.user)




#=========================
#  Tasks 
#=========================

class Task(models.Model):

    uuid  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user  = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
    name  = models.CharField('Task name', max_length=36, blank=False, null=False)

    # Task management
    id        = models.CharField('Task ID', max_length=64, blank=True, null=True) # i.e. Slurm job id, singularity PID, docker hash
    status    = models.CharField('Task status', max_length=36, blank=True, null=True)
    created   = models.DateTimeField('Created on', default=timezone.now)

    # How to reach the task interface. The IP has to be intended either as the container IP if this is directly
    # reachable (i.e. using a Docker or Kubernetes network) or as the host IP address, depending on the
    # computing resource and its computing manager/WMS/container runtime. The port is to be intended
    # as the port where the task interface is exposed on its IP address.
    interface_ip   = models.CharField('Task interface ip address', max_length=36, blank=True, null=True)
    interface_port = models.IntegerField('Task interface port', blank=True, null=True) 
    
    # Task access
    requires_tcp_tunnel = models.BooleanField('Does the task require a tunnel to be opened for accessing its interface?')
    tcp_tunnel_port     = models.IntegerField('Task tunnel port', blank=True, null=True)
    requires_proxy      = models.BooleanField('Does the task require a proxy for accessing its interface?')
    requires_proxy_auth = models.BooleanField('Does the task require interface authentication to be enforced at proxy-level?')
    auth_token          = models.CharField('A one-time token for proxy or interface authentication', max_length=36, blank=True, null=True)

    # Links
    computing = models.ForeignKey(Computing, related_name='+', on_delete=models.CASCADE)
    container = models.ForeignKey('Container', on_delete=models.CASCADE, related_name='+')

    # Extra 
    extra_binds = models.CharField('Task container extra binds', max_length=4096, blank=True, null=True)
    computing_options = JSONField('Task computing options', blank=True, null=True) # i.e. CPUs, RAM, cluster partition etc. TODO: why here?

    class Meta:
        ordering = ['-created']

    def save(self, *args, **kwargs):
        
        try:
            getattr(TaskStatuses, str(self.status))
        except AttributeError:
            raise Exception('Invalid status "{}"'.format(self.status))

        # Call parent save
        super(Task, self).save(*args, **kwargs)

    def update_status(self):
        if self.computing == 'local':
            
            check_command = 'sudo docker inspect --format \'{{.State.Status}}\' ' + self.tid # or, .State.Running
            out = os_shell(check_command, capture=True)
            logger.debug('Status: "{}"'.format(out.stdout))
            if out.exit_code != 0: 
                if (('No such' in out.stderr) and (self.tid in out.stderr)):
                    logger.debug('Task "{}" is not running in reality'.format(self.tid))
                self.status = TaskStatuses.exited
            else:
                if out.stdout == 'running':
                    self.status = TaskStatuses.running
                    
                elif out.stdout == 'exited':
                    self.status = TaskStatuses.exited
                    
                else:
                    raise Exception('Unknown task status: "{}"'.format(out.stdout))
                
            self.save()                   

    #@property
    #def id(self):
    #    return str(self.uuid).split('-')[0]


    def __str__(self):
        return str('Task "{}" of user "{}" running on "{}" in status "{}" created at "{}"'.format(self.name, self.user, self.computing, self.status, self.created))

    @property
    def color(self):
        string_int_hash = hash_string_to_int(self.name)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]
    
    @property
    def sharable_link(self):
        return '{}/t/{}'.format(settings.DJANGO_PUBLIC_HTTP_HOST, str(self.uuid)[0:8])
    
    @property
    def tcp_tunnel_host(self):
        # If separate host for tasks is set use that, otherwise:
        return settings.DJANGO_PUBLIC_HTTP_HOST


#=========================
#  KeyPair 
#=========================

class KeyPair(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE, null=False)  

    private_key_file = models.CharField('Private key file', max_length=4096, blank=False, null=False)
    public_key_file  = models.CharField('Public key file', max_length=4096, blank=False, null=False)

    default = models.BooleanField('Default keys?', default=False)


    def __str__(self):
        return str('KeyPair with id "{}" of user "{}"'.format(self.id, self.user))


    @property
    def id(self):
        return str(self.uuid).split('-')[0]



#=========================
#  Texts 
#=========================

class Text(models.Model):
    '''A model to store some text contents for the platform, like the home page text'''

    id = models.CharField('Text id', max_length=16, primary_key=True)
    content = models.TextField('Text content', blank=True, null=True)

    def __str__(self):
        return str('Text with id "{}"'.format(self.id))





