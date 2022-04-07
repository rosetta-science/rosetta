import os
import re
import uuid
import magic
import logging
from django.http import HttpResponse
from django.utils import timezone
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status, serializers, viewsets
from rest_framework.views import APIView
from .utils import format_exception, send_email, os_shell, now_t, get_ssh_access_mode_credentials, get_or_create_container_from_repository
from .models import Profile, Task, TaskStatuses, Computing, Storage, KeyPair
from .exceptions import ConsistencyException
import json
 
# Setup logging
logger = logging.getLogger(__name__)


#==============================
#  Common returns
#==============================
 
# Ok (with data)
def ok200(data=None):
    return Response({"results": data}, status=status.HTTP_200_OK)
 
# Error 400
def error400(data=None):
    return Response({"detail": data}, status=status.HTTP_400_BAD_REQUEST)
 
# Error 401
def error401(data=None):
    return Response({"detail": data}, status=status.HTTP_401_UNAUTHORIZED)
 
# Error 404
def error404(data=None):
    return Response({"detail": data}, status=status.HTTP_404_NOT_FOUND)
 
# Error 500
def error500(data=None):
    return Response({"detail": data}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


 
#==============================
#  Authentication helper
#==============================
 
def rosetta_authenticate(request):

    # Get data
    user      = request.user if request.user.is_authenticated else None
    username  = request.data.get('username', None)
    password  = request.data.get('password', None)
    authtoken = request.data.get('authtoken', None)

    # Try standard user authentication
    if user:
        return user

    # Try username/password  authentication
    elif username or password:
        
        # Check we got both
        if not username:
            return error400('Got empty username')
        if not password:
            return error400('Got empty password')
 
        # Authenticate
        user = authenticate(username=username, password=password)
        if not user:
            return error401('Wrong username/password')  
        else:
            login(request, user)
            return user

    # Try auth toekn authentication 
    elif authtoken:
        try:
            profile = Profile.objects.get(authtoken=authtoken)
        except Profile.DoesNotExist:
            return error400('Wrong auth token')
        login(request, profile.user)
        return profile.user
    else:
        return error401('This is a private API. Login or provide username/password or auth token')


#==============================
#  CSRF exempt auth class
#==============================

from rest_framework.authentication import SessionAuthentication, BasicAuthentication 

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


#==============================
#  Base public API class
#==============================
 
class PublicPOSTAPI(APIView):
    '''Base public POST API class'''
 
    # POST
    def post(self, request):
        try:
            return self._post(request)
        except Exception as e:
            logger.error(format_exception(e))
            return error500('Got error in processing request: {}'.format(e))
 
class PublicGETAPI(APIView):
    '''Base public GET API class''' 
    # GET
    def get(self, request):
        try:
            return self._get(request)
        except Exception as e:
            logger.error(format_exception(e))
            return error500('Got error in processing request: {}'.format(e))



#==============================
#  Base private API class
#==============================
 
class PrivatePOSTAPI(APIView):
    '''Base private POST API class'''
 
    # POST
    def post(self, request):
        try:
            # Authenticate using rosetta authentication
            response = rosetta_authenticate(request)
             
            # If we got a response return it, otherwise set it as the user.
            if isinstance(response, Response):
                return response
            else:
                self.user = response
             
            # Call API logic
            return self._post(request)
        except Exception as e:
            logger.error(format_exception(e))
            return error500('Got error in processing request: {}'.format(e))
 
class PrivateGETAPI(APIView):
    '''Base private GET API class'''

    # GET  
    def get(self, request):
        try:
            # Authenticate using rosetta authentication
            response = rosetta_authenticate(request)
             
            # If we got a response return it, otherwise set it as the user.
            if isinstance(response, Response):
                return response
            else:
                self.user = response
             
            # Call API logic
            return self._get(request)
        except Exception as e:
            logger.error(format_exception(e))
            return error500('Got error in processing request: {}'.format(e))



#==============================
#  User & profile APIs
#==============================

class login_api(PrivateGETAPI, PrivatePOSTAPI):
    """
    get:
    Returns the auth token.

    post:
    Authorize and returns the auth token.
    """
         
    def _post(self, request):
        return ok200({'authtoken': self.user.profile.authtoken})

    def _get(self, request):
        return ok200({'authtoken': self.user.profile.authtoken}) 
 
 
class logout_api(PrivateGETAPI):
    """
    get:
    Logout the user
    """
         
    def _get(self, request):
        logout(request)
        return ok200()


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Users to be viewed or edited.
    """

    class UserSerializer(serializers.HyperlinkedModelSerializer):
        class Meta:
            model = User
            fields = ('url', 'username', 'email', 'groups')

    queryset = User.objects.all().order_by('-date_joined')    
    serializer_class = UserSerializer


class agent_api(PublicGETAPI):
    
    def _get(self, request):
        
        task_uuid = request.GET.get('task_uuid', None)
        if not task_uuid:
            return HttpResponse('MISSING task_uuid')

        from django.core.exceptions import ValidationError

        try:
            task = Task.objects.get(uuid=task_uuid)
        except (Task.DoesNotExist, ValidationError):
            return HttpResponse('Unknown task uuid "{}"'.format(task_uuid))


        from.utils import get_webapp_conn_string
        webapp_conn_string = get_webapp_conn_string()
        
        action = request.GET.get('action', None)
        
        if not action:
            # Return the agent code
            agent_code='''
import logging
import socket
try:
    from urllib.request import urlopen
except ImportError:
    from urllib import urlopen

# Setup logging
logger = logging.getLogger('Agent')
logging.basicConfig(level=logging.INFO)

hostname = socket.gethostname()

# Task id set by the API
task_uuid = "'''+ task_uuid  +'''"

# Log
logger.info('Reporting for task uuid: "{}"'.format(task_uuid))

# Get IP
ip = socket.gethostbyname(hostname)
logger.info(' - ip: "{}"'.format(ip))

# Get port
from random import randint
while True:

    # Get a random ephimeral port
    port = randint(49152, 65535-2)

    # Check port is available
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result1 = sock.connect_ex(('127.0.0.1', port))
    result2 = sock.connect_ex(('127.0.0.1', port+1))
    result3 = sock.connect_ex(('127.0.0.1', port+2))
    if (result1 == 0) or (result2 == 0) or (result3 == 0):
        logger.info('Found not available ephemeral port triplet ({},{},{}) , choosing another one...'.format(port,port+1,port+2))
        import time
        time.sleep(1)
    else:
        break
logger.info(' - ports: "{},{},{}"'.format(port, port+1, port+2))

response = urlopen("'''+webapp_conn_string+'''/api/v1/base/agent/?task_uuid={}&action=set_ip_port&ip={}&port={}".format(task_uuid, ip, port))
response_content = response.read() 
if response_content not in ['OK', b'OK']:
    logger.error(response_content)
    logger.info('Not everything OK, exiting with status code =1')
    import sys
    sys.exit(1)
else:
    logger.info('Everything OK')
print(port)
'''
        
            return HttpResponse(agent_code)


        elif action=='set_ip_port':
            
            task_interface_ip   = request.GET.get('ip', None)
            if not task_interface_ip:
                return HttpResponse('IP not valid (got "{}")'.format(task_interface_ip))
            
            task_interface_port = request.GET.get('port', None)
            if not task_interface_port:
                return HttpResponse('Port not valid (got "{}")'.format(task_interface_port))
            
            try:
                int(task_interface_port)
            except (TypeError, ValueError):
                return HttpResponse('Port not valid (got "{}")'.format(task_interface_port))
              
            # Set fields
            logger.info('Agent API setting task "{}" to ip "{}" and port "{}"'.format(task.uuid, task_interface_ip, task_interface_port))
            task.status = TaskStatuses.running
            task.interface_ip = task_interface_ip
            
            # Get container engine
            container_engine = None
            if task.computing_options:
                container_engine = task.computing_options.get('container_engine', None)
            if not container_engine:
                container_engine = task.computing.default_container_engine
            
            if container_engine=='singularity':
                # For Singularity, set this only if the container supports custom
                # interface ports. Otherwise, use the task container interface port.
                if task.container.supports_custom_interface_port:
                    task.interface_port = int(task_interface_port)
                else:
                    task.interface_port = task.container.interface_port
            else:
                # For all other container engines, set it in any case
                task.interface_port = int(task_interface_port)
            
            # Save the task
            task.save()
                    
            # Notify the user that the task called back home if using a WMS
            if task.computing.wms:
                if settings.DJANGO_EMAIL_APIKEY:
                    logger.info('Agent API sending task ready mail notification to "{}"'.format(task.user.email))
                    mail_subject = 'Your Task "{}" is now starting up'.format(task.container.name)
                    mail_text = 'Hello,\n\nyour Task "{}" on {} is now starting up. Check logs or connect here: https://{}/tasks/?uuid={}\n\nThe Rosetta notifications bot.'.format(task.container.name, task.computing, settings.ROSETTA_HOST, task.uuid)
                    try:
                        send_email(to=task.user.email, subject=mail_subject, text=mail_text)
                    except Exception as e:
                        logger.error('Cannot send task ready email: "{}"'.format(e))
            return HttpResponse('OK')
            

        else:
            return HttpResponse('Unknown action "{}"'.format(action))


#==========================================
# File manager APIs
#==========================================

class FileManagerAPI(PrivateGETAPI, PrivatePOSTAPI):
    """
    get:
    Return directory listings or file contents.

    post:
    Perform actions or upload files.
    """
    
    # The RichFilemanager has no CSRF support...
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)


    def scp_command(self, source, dest, user, computing, mode='get'):

        # Prepare paths for scp. They have been already made shell-ready, but we need to triple-escape
        # spaces on remote source or destination: My\ Folder mut become My\\\ Folder.
        
        if mode=='get':
            source = source.replace('\ ', '\\\\\\ ')
        else:
            dest = dest.replace('\ ', '\\\\\\ ')
        
        # Get credentials
        computing_user, computing_host, computing_keys = get_ssh_access_mode_credentials(computing, user)

        # Command
        if mode=='get':
            command = 'scp -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{}:{} {}'.format(computing_keys.private_key_file, computing_user, computing_host, source, dest)
        elif mode == 'put':
            command = 'scp -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {} {}@{}:{}'.format(computing_keys.private_key_file, source, computing_user, computing_host, dest)
        else:
            raise ValueError('Unknown mode "{}"'.format(mode))

        return command


    def ssh_command(self, command, user, computing):

        # Get credentials
        computing_user, computing_host, computing_keys = get_ssh_access_mode_credentials(computing, user)

        # Command
        command = 'ssh -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} "{}"'.format(computing_keys.private_key_file, computing_user, computing_host, command)

        return command

    @staticmethod
    def clean_path(path):
        cleaner = re.compile('(?:\/)+')
        path = re.sub(cleaner,'/',path)
        return path

    @staticmethod
    def sanitize_shell_path(path):
        path = path.replace(' ', '\ ')
        cleaner = re.compile('(?:\\\)+')
        path = re.sub(cleaner,r"\\",path)
        return path

    @staticmethod
    def sanitize_and_prepare_shell_path(path, storage, user):
        path = path.replace(' ', '\ ')
        cleaner = re.compile('(?:\\\)+')
        path = re.sub(cleaner,r"\\",path)
                
        # Prepare the base path (expand it with variables substitution)
        base_path_expanded = storage.base_path        
        if '$SSH_USER' in base_path_expanded:
            if storage.access_through_computing:
                computing = storage.computing
                if computing.auth_mode == 'user_keys':
                    computing_user = user.profile.get_extra_conf('computing_user', storage.computing)
                    if not computing_user:
                        raise ValueError('No \'computing_user\' parameter found for computing resource \'{}\' in user profile'.format(storage.computing.name))
                    base_path_expanded = base_path_expanded.replace('$SSH_USER', computing_user)
                else:
                    base_path_expanded = base_path_expanded.replace('$SSH_USER', computing.conf.get('user'))
                    
            else:
                raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
        if '$USER' in base_path_expanded:
            base_path_expanded = base_path_expanded.replace('$USER', user.username)

        # If the path is not starting with the base path, do it
        if not path.startswith(base_path_expanded):
            path = base_path_expanded+'/'+path
            
        return path

    def get_storage_from_path(self, path, request):
        # Get the storage based on the "root" folder name
        # TODO: this is extremely weak..
        storage_id = path.split('/')[1]
        try:
            computing_name = storage_id.split(':')[0]
            storage_name = storage_id.split(':')[1]
        except IndexError:
            storage_name = storage_id
            computing_name = None
            
        # Get all the storages this user has access to:
        storages = list(Storage.objects.filter(group=None, name=storage_name)) + list(Storage.objects.filter(group__user=request.user, name=storage_name))
        
        # Filter by computing resource name (or None)
        if computing_name:
            unfiltered_storages = storages
            storages = []
            for storage in unfiltered_storages:
                if storage.computing.name == computing_name:
                    storages.append(storage)
        else:
            unfiltered_storages = storages
            storages = []
            for storage in unfiltered_storages:
                if storage.computing is None:
                    storages.append(storage)            
            

        # Check that we had at least and no more than one storage in the end
        if len(storages) == 0:
            raise Exception('Found no storage for id "{}", cannot continue!'.format(storage_id))
        if len(storages) > 1:
            raise Exception('Found more than one storage for id "{}", cannot continue!'.format(storage_id))

        # Assign the storage
        storage = storages[0]

        return storage
                

    def ls(self, path, user, storage):
        
        # Data container 
        data = []
        
        shell_path = self.sanitize_and_prepare_shell_path(path, storage, user)
        
        # Prepare command
        # https://askubuntu.com/questions/1116634/ls-command-show-time-only-in-iso-format
        # https://www.howtogeek.com/451022/how-to-use-the-stat-command-on-linux/
        command = self.ssh_command('cd {} && stat --printf=\'%F/%s/%Y/%n\\n\' * .*'.format(shell_path), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            
            # Did we just get a "cannot stat - No such file or directory error?
            if 'No such file or directory' in out.stderr:
                pass
            else:
                raise Exception(out.stderr)
                            
        # Log        
        #logger.debug('Shell exec output: "{}"'.format(out))
        
        out_lines = out.stdout.split('\n')
        
        for line in out_lines:
            
            # Example line: directory/My folder/68/1617030350

            # Set name
            line_pieces = line.split('/')
            type = line_pieces[0]
            size = line_pieces[1]
            timestamp = line_pieces[2]
            name = line_pieces[3]
                     
            # Define and clean listing path:
            listing_path = '/{}/{}/{}/'.format(storage.id, path, name)
            listing_path = self.clean_path(listing_path)
        
            # File or directory?
            if type == 'directory':
                if name not in ['.', '..']:
                    data.append({
                                 'id': listing_path,
                                 'type': 'folder',
                                 'attributes':{
                                      'modified': timestamp,
                                      'name': name,
                                      'readable': 1,
                                      'writable': 1,
                                      'path': listing_path                                 
                                  }
                                 })
            else:
                data.append({
                             'id': listing_path[:-1], # Remove trailing slash 
                             'type': 'file',
                             'attributes':{
                                  'modified': timestamp,
                                  'name': name,
                                  'readable': 1,
                                  'writable': 1,
                                  "size": size,
                                  'path': listing_path[:-1] # Remove trailing slash                               
                              }
                             })                            
            
            
        return data


    def stat(self, path, user, storage):
        
        path = self.sanitize_and_prepare_shell_path(path, storage, user)
        
        # Prepare command. See the ls function above for some more info
        command = self.ssh_command('stat --printf=\'%F/%s/%Y/%n\\n\' {}'.format(path), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            
            # Did we just get a "cannot stat - No such file or directory error?
            if 'No such file or directory' in out.stderr:
                pass
            else:
                raise Exception(out.stderr)
                            
        # Log        
        #logger.debug('Shell exec output: "{}"'.format(out))
        
        out_lines = out.stdout.split('\n')
        if len(out_lines) > 1:
            raise Exception('Internal error on stat: more than one ouput line')
        out_line = out_lines[0]
    
        # Example output line: directory:My folder:68/1617030350
        # In this context, we also might get the following output:
        # directory/68/1617030350//My folder/
        # ..so, use the clean path to remove all extra slashes.
        # The only uncovered case is to rename the root folder...
        
        out_line = self.clean_path(out_line)

        # Set names
        line_pieces = out_line.split('/')
        type = line_pieces[0]
        size = line_pieces[1]
        timestamp = line_pieces[2]
        name = '/'.join(line_pieces[3:])
        
        return {'type': type, 'name': name, 'size': size, 'timestamp': timestamp}
            


    def delete(self, path, user, storage):

        path = self.sanitize_and_prepare_shell_path(path, storage, user)

        # Prepare command
        command = self.ssh_command('rm -rf {}'.format(path), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def mkdir(self, path, user, storage):
        
        path = self.sanitize_and_prepare_shell_path(path, storage, user)
        
        # Prepare command
        command = self.ssh_command('mkdir {}'.format(path), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def cat(self, path, user, storage):
        
        path = self.sanitize_and_prepare_shell_path(path, storage, user)
        
        # Prepare command
        command = self.ssh_command('cat {}'.format(path), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def rename(self, old, new, user, storage):
        
        old = self.sanitize_and_prepare_shell_path(old, storage, user)
        new = self.sanitize_and_prepare_shell_path(new, storage, user)

        # Prepare command
        command = self.ssh_command('mv {} {}'.format(old, new), user, storage.computing)

        logger.critical(command)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def copy(self, source, target, user, storage):

        source = self.sanitize_and_prepare_shell_path(source, storage, user)
        target = self.sanitize_and_prepare_shell_path(target, storage, user)

        # Prepare command
        command = self.ssh_command('cp -a {} {}'.format(source, target), user, storage.computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def scp_from(self, source, target, user, storage, mode='get'):

        source = self.sanitize_and_prepare_shell_path(source, storage, user)
        target = self.sanitize_shell_path(target) # This is a folder on Rosetta (/tmp)

        # Prepare command
        command = self.scp_command(source, target, user, storage.computing, mode)

        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)


    def scp_to(self, source, target, user, storage, mode='get'):

        source = self.sanitize_shell_path(source) # This is a folder on Rosetta (/tmp)
        target = self.sanitize_and_prepare_shell_path(target, storage, user)

        # Prepare command
        command = self.scp_command(source, target, user, storage.computing, mode)

        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)


    #============================
    #   API GET
    #============================
    def _get(self, request):
        
        mode = request.GET.get('mode', None)
        time = request.GET.get('time', None)
        path = request.GET.get('path', None)
        _ = request.GET.get('_', None)
        
        # Clean for some issues that happen sometimes
        if path:
            path = self.clean_path(path)
        
        # Init
        if mode == 'initiate':
            data = json.loads('{"data":{"attributes":{"config":{"options":{"culture":"en"},"security":{"allowFolderDownload":true,"extensions":{"ignoreCase":true,"policy":"DISALLOW_LIST","restrictions":[]},"readOnly":false}}},"id":"/","type":"initiate"}}')

        elif mode == 'readfolder':
            
            # Base folder (computing resource-level)
            if path == '/':
                
                # Data container 
                data = {'data':[]}
                
                # Get storages
                storages = list(Storage.objects.filter(group=None)) + list(Storage.objects.filter(group__user=request.user))
                
                # Oder storages (re-orderded in the file manager anyway)
                storages.sort(key=lambda storage: storage.id)
                
                # Prepare the output
                for storage in storages:
                    
                    # For now, we only support generic posix, SSH-based storages
                    if not storage.type=='generic_posix'  and storage.access_mode=='ssh+cli':
                        continue
                    
                    if storage.access_through_computing and not storage.computing.manager.is_configured_for(user=request.user):
                        continue
                    
                    data['data'].append({
                                         'id': '/{}/'.format(storage.id),
                                         'type': 'folder',
                                         'attributes':{
                                              'name': storage.id,
                                              'readable': 1,
                                              'writable': 1,
                                              'path': '/{}/'.format(storage.id)                                   
                                          }
                                         })
                
            else:
                                
                storage = self.get_storage_from_path(path, request)
                
                # Get base directoris and files for this storage:                
                ls_path = '/'+'/'.join(path.split('/')[2:])
                data = {'data': self.ls(ls_path, request.user, storage)}


        elif mode in ['download', 'getimage']:
            logger.debug('Downloading "{}"'.format(path))
            
            if path.endswith('/'):
                return error400('Downloading a folder is not supported')
            
            # TOOD: here we are not handling ajax request, Maybe they have been deperacted?
            # The download process consists of 2 requests:
            #  - Ajax GET request. Perform all checks and validation. Should return file/folder object in the response data to proceed.
            #  - Regular GET request. Response headers should be properly configured to output contents to the browser and start download.
            # See here: https://github.com/psolom/RichFilemanager/wiki/API

            # Set support vars
            storage = self.get_storage_from_path(path, request)
            file_path = '/'+'/'.join(path.split('/')[2:])
            target_path = '/tmp/{}'.format(uuid.uuid4())

            # Get the file
            self.scp_from(file_path, target_path, request.user, storage, mode='get') 

            # Detect content type
            try:
                content_type =  str(magic.from_file(target_path, mime=True))
            except:
                content_type = None

            # Read file data
            with open(target_path, 'rb') as f:
                data = f.read()
            
            # Remove file
            os.remove(target_path)
            
            # Return file data
            response = HttpResponse(data, status=status.HTTP_200_OK, content_type=content_type)
            response['Content-Disposition'] = 'attachment; filename="{}"'.format(file_path.split('/')[-1])
            return response

        elif mode == 'readfile':
            logger.debug('Reading "{}"'.format(path))
            
            # Set support vars
            storage = self.get_storage_from_path(path, request)
            file_path = '/'+'/'.join(path.split('/')[2:])

            # Get file contents
            data = self.cat(file_path, request.user, storage)
            
            # Return file contents
            return HttpResponse(data, status=status.HTTP_200_OK)


        elif mode == 'delete':
            logger.debug('Deleting "{}"'.format(path))
            
            # Set support vars
            storage = self.get_storage_from_path(path, request)
            path = '/'+'/'.join(path.split('/')[2:])

            # Is it a folder?
            if path.endswith('/'):
                is_folder=True
            else:
                is_folder=False

            # Get file contents
            data = self.delete(path, request.user, storage)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(storage.id, path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'name': path,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(storage.id, path)                            
                            }
                        }
                    }      
            
            
            # Return file contents
            return Response(data, status=status.HTTP_200_OK)
            

        elif mode == 'addfolder':
            logger.debug('Deleting "{}"'.format(path))
            
            name = request.GET.get('name', None)
            if not name:
                raise ValueError('No folder name set')
            
            # Set support vars
            storage = self.get_storage_from_path(path, request)
            path = '/'+'/'.join(path.split('/')[2:]) + name

            # Get file contents
            data = self.mkdir(path, request.user, storage)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(storage.id, path),
                            'type': 'folder',
                            'attributes':{
                                'modified': now_t(), # This is an approximation!
                                'name': name,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(storage.id, path)                            
                            }
                        }
                    }      
            
            
            # Return file contents
            return Response(data, status=status.HTTP_200_OK)


        elif mode == 'rename':
            logger.debug('Renaming "{}"'.format(path))
            
            # Get old file name with path
            old_name_with_path = request.GET.get('old', None)
            if not old_name_with_path:
                raise Exception('Missing old name')            
            
            # Set support vars
            storage = self.get_storage_from_path(old_name_with_path, request)
            old_name_with_path = '/'+'/'.join(old_name_with_path.split('/')[2:])
            
            # Is it a folder?
            if old_name_with_path.endswith('/'):
                is_folder=True
            else:
                is_folder=False

            # Get new name
            new_name = request.GET.get('new', None)
            if not new_name:
                raise Exception('Missing new name')
            
            if is_folder:
                new_name_with_path = '/'.join(old_name_with_path.split('/')[:-2]) + '/' +  new_name
                old_name_with_path = old_name_with_path[:-1]

            new_name_with_path = '/'.join(old_name_with_path.split('/')[:-1]) + '/' +  new_name

            # Rename
            self.rename(old_name_with_path, new_name_with_path, request.user, storage)
            
            # Add trailing slash for listing
            if is_folder:
                new_name_with_path = new_name_with_path+'/'
            
            # Get new info
            stat = self.stat(new_name_with_path, request.user, storage)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(storage.id, new_name_with_path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'modified':   stat['timestamp'],
                                'name': new_name,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(storage.id, new_name_with_path)                              
                            }
                        }
                    }      
            
            # Add size if file
            if not is_folder: data['data']['attributes']['size'] = stat['size']
            
            # Return file contents
            return Response(data, status=status.HTTP_200_OK)


        elif mode == 'copy':
            logger.debug('Copying "{}"'.format(path))
            
            # Get source for copy
            source_name_with_path = request.GET.get('source', None)
            if not source_name_with_path:
                raise Exception('Missing source for copy') 
            
            # Get target for copy
            target_path = request.GET.get('target', None)
            if not target_path:
                raise Exception('Missing target for copy')
            

            if source_name_with_path.endswith('/'):
                is_folder=True
            else:
                is_folder=False


            # Set support vars
            storage = self.get_storage_from_path(source_name_with_path, request)
            
            if is_folder:
                source_name_with_path = '/'+'/'.join(source_name_with_path.split('/')[2:])[:-1]
                target_name_with_path = '/'+'/'.join(target_path.split('/')[2:]) +  source_name_with_path.split('/')[-1]            
            else:
                source_name_with_path = '/'+'/'.join(source_name_with_path.split('/')[2:])
                target_name_with_path = '/'+'/'.join(target_path.split('/')[2:]) +  source_name_with_path.split('/')[-1]


            # Redefine target if copying in the same folder
            if source_name_with_path == target_name_with_path:
                target_name_with_path = target_name_with_path+'.copy'

            #logger.debug('Copy source: "{}"'.format(source_name_with_path))
            #logger.debug('Copy target: "{}"'.format(target_name_with_path))

            # Rename
            self.copy(source_name_with_path, target_name_with_path, request.user, storage)

            # Add trailing slash for listing
            if is_folder:
                target_name_with_path = target_name_with_path + '/'

            # Get new info
            stat = self.stat(target_name_with_path, request.user, storage)
 
            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(storage.id, target_name_with_path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'modified': stat['timestamp'],
                                'name': target_name_with_path.split('/')[-2] if is_folder else target_name_with_path.split('/')[-1],
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(storage.id, target_name_with_path)                            
                            }
                        }
                    }

            # Add size if file
            if not is_folder: data['data']['attributes']['size'] = stat['size']      
            
            # Return file contents
            return Response(data, status=status.HTTP_200_OK)

        
        else:
            return error400('Operation "{}" not supported'.format(mode))

        
        return Response(data, status=status.HTTP_200_OK)


    #============================
    #   API POST 
    #============================
    def _post(self, request):

        mode = request.POST.get('mode', None)
        time = request.POST.get('time', None)
        path = request.POST.get('path', None)
        _ = request.GET.get('_', None)


        if mode == 'savefile':
            return error400('Operation "{}" not supported'.format(mode))
        
        elif mode == 'upload':

            # Set support vars
            storage = self.get_storage_from_path(path, request)
            path = '/'+'/'.join(path.split('/')[2:])

            # Get the file upload
            file_upload = request.FILES['files']
            
            # generate temporary UUID
            file_uuid = uuid.uuid4()
            
            with open('/tmp/{}'.format(file_uuid), 'wb') as temp_file:
                temp_file.write(file_upload.read())
            
            logger.debug('Wrote "/tmp/{}" for "{}"'.format(file_uuid, file_upload.name))

            # Now copy with scp
            self.scp_to('/tmp/{}'.format(file_uuid), path + file_upload.name , request.user, storage, mode='put')
        
            # Response data
            data = { 'data': [{
                            'id': '/{}{}{}'.format(storage.id, path, file_upload.name),
                            'type': 'file',
                            'attributes':{
                                'modified': now_t(),  # This is an approximation!
                                'name': file_upload.name,
                                'readable': 1,
                                'size': os.path.getsize('/tmp/{}'.format(file_uuid)), # This is kind of an approximation!
                                'writable': 1,
                                'path': '/{}{}{}'.format(storage.id, path, file_upload.name)                            
                            }
                        }]
                    }
            
            # Remove file
            os.remove('/tmp/{}'.format(file_uuid))
                        
            # Return
            return Response(data, status=status.HTTP_200_OK)
        
        else:
            return error400('Operation "{}" not supported'.format(mode))

        return ok200('ok')


#==============================
#  Import repository APIs
#==============================

class ImportRepositoryAPI(PrivateGETAPI):
    """
    get:
    Import a repository as a container and get the container uuid.

    """

    def _get(self, request):
        
        repository_url = request.GET.get('repository_url', None)
        repository_tag = request.GET.get('repository_tag', None)
        container_name = request.GET.get('container_name', None)
        container_description = request.GET.get('container_description', None)

        if not repository_url:
            return error400('Missing "repository_url"')

        if not repository_tag:
            return error400('Missing "repository_tag"')
  
        logger.debug('Importing repository "%s" with tag "%s"', repository_url, repository_tag)

        results = {}
        try:     
            container = get_or_create_container_from_repository(request.user, repository_url, repository_tag, container_name, container_description)
        except Exception as e:
            results['import_succeded'] = False
            results['error_message'] = str(e)
        else:
            results['import_succeded'] = True
            results['container_uuid'] = str(container.uuid)
             
        return ok200(results) 





