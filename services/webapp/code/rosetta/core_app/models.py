import uuid
import json
import base64
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User, Group
from django.utils import timezone
from .utils import os_shell, color_map, hash_string_to_int, get_task_tunnel_host
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
    auth      = models.CharField('User auth mode', max_length=36)
    timezone  = models.CharField('User Timezone', max_length=36, default='UTC')
    authtoken = models.CharField('User auth token', max_length=36, blank=True, null=True) # This is used for testing, not a login token.
    is_power_user = models.BooleanField('Power user status', default=False)
    extra_confs   = JSONField(blank=True, null=True)


    def save(self, *args, **kwargs):
        if not self.authtoken:
            self.authtoken = str(uuid.uuid4())
        super(Profile, self).save(*args, **kwargs)


    def __str__(self):
        return str('Profile of user "{}"'.format(self.user.email))


    def add_extra_conf(self, conf_type, object=None, value=None):
        if value in [None, '']: # TODO: improve me?
            raise ValueError('Empty value')
        if self.extra_confs is None:
            self.extra_confs = {}
        self.extra_confs[str(uuid.uuid4())] = {'type': conf_type, 'object_uuid': str(object.uuid), 'value': value}
        self.save()
        

    def get_extra_conf(self, conf_type, object=None):
       
        if self.extra_confs:
            for extra_conf in self.extra_confs:
                if conf_type == self.extra_confs[extra_conf]['type']:
                    if object:
                        #logger.debug("{} vs {}".format(self.extra_confs[extra_conf]['object_uuid'], str(object.uuid)))
                        if self.extra_confs[extra_conf]['object_uuid'] == str(object.uuid):
                            return self.extra_confs[extra_conf]['value']                        
                    else:
                        return self.extra_confs[extra_conf]['value']
        return None
            


#=========================
#  Login Token 
#=========================

class LoginToken(models.Model):

    uuid  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user  = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField('Login token', max_length=36)

    def __str__(self):
        return str('Login token of user "{}"'.format(self.user.email))



#=========================
#  Containers
#=========================
class Container(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='containers', on_delete=models.CASCADE, blank=True, null=True)  
    # If a container has no user, it will be available to anyone. Can be created, edited and deleted only by admins.
    group = models.ForeignKey(Group, related_name='containers', on_delete=models.CASCADE, blank=True, null=True)
    # If a container has no group, it will be available to anyone. Can be created, edited and deleted only by admins.

    # Generic attributes
    name        = models.CharField('Name', max_length=255, blank=False, null=False)
    description = models.TextField('Description', blank=True, null=True)
    
    # Registry
    registry = models.CharField('Registry', max_length=255, blank=False, null=False)

    # Image name
    image_name = models.CharField('Image', max_length=255, blank=False, null=False)
    
    # Image identifiers
    image_tag  = models.CharField('Tag', max_length=255, blank=True, null=True, default='latest')
    image_arch = models.CharField('Architecture', max_length=36, blank=True, null=True)
    image_os   = models.CharField('Operating system', max_length=36, blank=True, null=True)
    # -- OR --
    image_digest  = models.CharField('SHA 256 digest', max_length=96, blank=True, null=True)
    
    # TODO: do we want more control with respect to kernel, CPUs, instruction sets? 
    # requires = i.e. kernel > 3, intel, AVX2
    
    # Port, protocol and transport for the container interface
    interface_port = models.IntegerField('Interface port', blank=True, null=True) 
    interface_protocol = models.CharField('Interface protocol', max_length=36, blank=True, null=True)
    interface_transport = models.CharField('Interface transport', max_length=36, blank=True, null=True)

    # Capabilities
    supports_custom_interface_port = models.BooleanField('Supports custom interface port', default=False) # BASE_PORT
    supports_interface_auth = models.BooleanField('Supports interface auth', default=False) # AUTH_USER / AUTH_PASS
    interface_auth_user = models.CharField('Interface auth fixed user if any', max_length=36, blank=True, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        user_str = self.user.email if self.user else None
        return str('Container "{}" of user "{}" with image name "{}" and image tag "{}" on registry "{}" '.format(self.name, user_str, self.image_name, self.image_tag, self.registry))

    def save(self, *args, **kwargs):
        # Check that digest starts with sha256:
        if self.image_digest and not self.image_digest.startswith('sha256:'):
            raise ValueError('The digest field must start with "sha256:"')
        
        super(Container, self).save(*args, **kwargs)

    @property
    def family_id(self):
        return base64.b64encode('{}\t{}\t{}'.format(self.name, self.registry, self.image_name).encode('utf8')).decode('utf8')


    @property
    def color(self):
        string_int_hash = hash_string_to_int(self.name + self.registry + self.image_name)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]




#=========================
#  Computing resources
#=========================

class Computing(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(Group, related_name='computings', on_delete=models.CASCADE, blank=True, null=True)
    # If a compute resource has no group, it will be available to anyone. Can be created, edited and deleted only by admins.
    
    name        = models.CharField('Name', max_length=255, blank=False, null=False)
    description = models.TextField('Description', blank=True, null=True)

    # Type (standalone / cluster) and arch
    type = models.CharField('Type', max_length=255, blank=False, null=False)
    arch = models.CharField('Architecture', max_length=255, blank=False, null=False)

    # Interfce and interaction definition
    access_mode = models.CharField('Access (control) mode', max_length=36, blank=False, null=False)
    auth_mode   = models.CharField('Auth mode', max_length=36, blank=False, null=False)
    wms         = models.CharField('Workload management system', max_length=36, blank=True, null=True)
    
    # Supported container runtimes ['docker', 'singularity']
    container_runtimes = JSONField('Container runtimes', blank=False, null=False)
    #container_runtime = models.CharField('Container runtimes', max_length=256, blank=False, null=False)
 
    # Emulated architectures, by container runtime {'docker': ['arm64', 'amd']    
    emulated_archs = JSONField('Emulated architectures', blank=True, null=True) 

    # Conf
    conf = JSONField(blank=True, null=True)


    class Meta:
        ordering = ['name']


    def __str__(self):
        if self.group:
            return str('Computing "{}" of group "{}"'.format(self.name, self.group))
        else:
            return str('Computing "{}"'.format(self.name))

    @property
    def uuid_as_str(self):
        return str(self.uuid)

    @property
    def color(self):
        string_int_hash = hash_string_to_int(self.name)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]

    @property
    def default_container_runtime(self):
        return str(self.container_runtimes).split(',')[0]
    
    @property
    def arch(self):
        return 'amd64'
    


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
            if self.type == 'cluster' and self.access_mode == 'ssh+cli' and self.auth_mode == 'user_keys' and self.wms == 'slurm':
                self._manager = computing_managers.SlurmSSHClusterComputingManager(self)
            elif self.type == 'standalone' and self.access_mode == 'ssh+cli' and self.auth_mode == 'user_keys' and self.wms is None:
                self._manager = computing_managers.SSHSingleNodeComputingManager(self)
            elif self.type == 'standalone' and self.access_mode == 'internal' and self.auth_mode == 'internal' and self.wms is None:
                self._manager = computing_managers.InternalSingleNodeComputingManager(self)
            else:
                raise ConsistencyException('Don\'t know how to instantiate a computing manager for computing resource of type "{}", access mode "{}" and WMS "{}"'.format(self.type, self.access_mode, self.wms))
            return self._manager
    

#=========================
#  Tasks 
#=========================

class Task(models.Model):

    uuid  = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user  = models.ForeignKey(User, related_name='tasks', on_delete=models.CASCADE)
    name  = models.CharField('Name', max_length=36, blank=False, null=False)

    # Task management
    id        = models.CharField('ID', max_length=64, blank=True, null=True) # i.e. Slurm job id, singularity PID, docker hash
    status    = models.CharField('Status', max_length=36, blank=True, null=True)
    created   = models.DateTimeField('Created on', default=timezone.now)

    # How to reach the task interface. The IP has to be intended either as the container IP if this is directly
    # reachable (i.e. using a Docker or Kubernetes network) or as the host IP address, depending on the
    # computing resource and its computing manager/WMS/container runtime. The port is to be intended
    # as the port where the task interface is exposed on its IP address.
    interface_ip   = models.CharField('Interface IP address', max_length=36, blank=True, null=True)
    interface_port = models.IntegerField('Interface port', blank=True, null=True) 
    
    # Task access
    requires_tcp_tunnel = models.BooleanField('Requires a TCP tunnel')
    tcp_tunnel_port     = models.IntegerField('TCP tunnel port', blank=True, null=True)
    requires_proxy      = models.BooleanField('Requires proxy')
    requires_proxy_auth = models.BooleanField('Requires proxy auth')
    auth_token          = models.CharField('Auth token', max_length=36, blank=True, null=True) # A one-time token for proxy or interface authentication

    # Links
    computing = models.ForeignKey(Computing, related_name='tasks', on_delete=models.CASCADE)
    container = models.ForeignKey('Container', on_delete=models.CASCADE, related_name='+')

    # Computing options
    # TODO: add the option for selecting the runtime as advanced option when creating the task?
    computing_options = JSONField('Computing options', blank=True, null=True) # i.e. CPUs, RAM, cluster partition etc. TODO: why here?
    
    
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


    def __str__(self):
        return str('Task "{}" of user "{}" running on "{}" in status "{}" created at "{}"'.format(self.name, self.user.email, self.computing, self.status, self.created))

    @property
    def color(self):
        string_int_hash = hash_string_to_int(self.name)
        color_map_index = string_int_hash % len(color_map)
        return color_map[color_map_index]
    
    @property
    def sharable_link(self):
        return 'https://{}/t/{}'.format(settings.ROSETTA_HOST, str(self.uuid)[0:8])
    
    @property
    def tcp_tunnel_host(self):
        return get_task_tunnel_host()





#=========================
#  Storages
#=========================

class Storage(models.Model):
 
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(Group, related_name='storages', on_delete=models.CASCADE, blank=True, null=True)
  
    name = models.CharField('Name', max_length=255, blank=False, null=False)
    #description = models.TextField('Description', blank=True, null=True)
 
    # Storage type
    type = models.CharField('Type', max_length=255, blank=False, null=False)
 
    # Access and auth mode 
    access_mode = models.CharField('Access (control) mode', max_length=36, blank=False, null=False)
    auth_mode   = models.CharField('Auth mode', max_length=36, blank=False, null=False)
     
    # Paths
    base_path = models.CharField('Base path', max_length=4096, blank=False, null=False) 
    bind_path = models.CharField('Bind path', max_length=4096, blank=False, null=False) 
 
    # Link with a computing resource
    computing = models.ForeignKey(Computing, related_name='storages', on_delete=models.CASCADE, blank=True, null=True) # Make optional?
    access_through_computing = models.BooleanField('Access through linked computing resource?', default=False)
    # If the above is linked, some configuration can be taken from the linked computing resource (i.e. the hostname)
 
    # Configuration
    conf = JSONField(blank=True, null=True)
 
 
    class Meta:
        ordering = ['name']
 
    def __str__(self):
        if self.group:
            return str('Storage "{}" of group "{}"'.format(self.id, self.group))
        else:
            return str('Storage "{}"'.format(self.id))
 
    @property
    def id(self):
        return (self.name if not self.computing else '{}:{}'.format(self.computing.name,self.name))
 




#=========================
#  KeyPair 
#=========================

class KeyPair(models.Model):

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='key_pairs', on_delete=models.CASCADE, blank=True, null=True)  

    private_key_file = models.CharField('Private key file', max_length=4096, blank=False, null=False)
    public_key_file  = models.CharField('Public key file', max_length=4096, blank=False, null=False)

    default = models.BooleanField('Default keys?', default=False)


    def __str__(self):
        return str('KeyPair of user "{}" (default={})'.format( self.user.email, self.default))



#=========================
#  Page 
#=========================

class Page(models.Model):
    '''A model to store pages for the platform, as custom a custom home page'''

    id = models.CharField('Page id', max_length=16, primary_key=True)
    content = models.TextField('Page content', blank=True, null=True)

    def __str__(self):
        return str('Page "{}"'.format(self.id))





