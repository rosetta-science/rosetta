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
from .utils import format_exception, send_email, os_shell, now_t
from .models import Profile, Task, TaskStatuses, Computing, KeyPair
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
if response_content != 'OK':
    logger.error(response_content)
    logger.info('Not everything OK, exiting with status code =1')
    sys.exit(1)
else:
    logger.info('Everything OK')
print(port)
'''
        
            return HttpResponse(agent_code)


        elif action=='set_ip_port':
            
            task_ip   = request.GET.get('ip', None)
            if not task_ip:
                return HttpResponse('IP not valid (got "{}")'.format(task_ip))
            
            task_port = request.GET.get('port', None)
            if not task_port:
                return HttpResponse('Port not valid (got "{}")'.format(task_port))
            
            try:
                int(task_port)
            except (TypeError, ValueError):
                return HttpResponse('Port not valid (got "{}")'.format(task_port))
              
            # Set fields
            logger.info('Setting task "{}" to ip "{}" and port "{}"'.format(task.uuid, task_ip, task_port))
            task.status = TaskStatuses.running
            task.ip     = task_ip
            if task.container.supports_dynamic_ports:
                task.port = int(task_port)
            task.save()
                    
            # Notify the user that the task called back home
            logger.info('Sending task ready mail notification to "{}"'.format(task.user.email))
            mail_subject = 'Your Task "{}" is now starting up'.format(task.container.name)
            mail_text = 'Hello,\n\nyour Task "{}" on {} is now starting up. Check logs or connect here: {}/tasks/?uuid={}\n\nThe Rosetta notifications bot.'.format(task.container.name, task.computing, settings.DJANGO_PUBLIC_HTTP_HOST, task.uuid)
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
            
        # Get user key
        user_keys = KeyPair.objects.get(user=user, default=True)
       
        # Get computing host
        computing_host = computing.conf.get('host')
        
        # Trick for handling Slurm.. TODO: fix me!
        if not computing_host:
            computing_host = computing.conf.get('master')
        
        computing_user = computing.conf.get('user')

        if not computing_host:
            raise Exception('No computing host?!')

        if not computing_user:
            raise Exception('No computing user?!')

        # Command
        if mode=='get':
            command = 'scp -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{}:{} {}'.format(user_keys.private_key_file, computing_user, computing_host, source, dest)
        elif mode == 'put':
            command = 'scp -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {} {}@{}:{}'.format(user_keys.private_key_file, source, computing_user, computing_host, dest)
        else:
            raise ValueError('Unknown mode "{}"'.format(mode))

        return command

    

    def ssh_command(self, command, user, computing):

        # Get user key
        user_keys = KeyPair.objects.get(user=user, default=True)
       
        # Get computing host
        computing_host = computing.conf.get('host')
        
        # Trick for handling Slurm.. TODO: fix me!
        if not computing_host:
            computing_host = computing.conf.get('master')
        
        computing_user = computing.conf.get('user')

        if not computing_host:
            raise Exception('No computing host?!')

        if not computing_user:
            raise Exception('No computing user?!')

        # Command
        command = 'ssh -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} "{}"'.format(user_keys.private_key_file, computing_user, computing_host, command)

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

    def get_computing(self, path, request):
        # Get the computing based on the folder name # TODO: this is very weak..
        computing_resource_name = path.split('/')[1]
        
        # First try to get platform-level computing resource
        computing = Computing.objects.filter(name=computing_resource_name, user=None)
        
        # If not, fallback on the user computing name
        if not computing:
            computing = Computing.objects.filter(name=computing_resource_name, user=request.user)
            
            if not computing:
                raise Exception('Cannot find any computing resource named "{}"'.format(computing_resource_name+'1'))
        
        # Check that we had no more than one computing resource
        if len(computing) > 1:
            raise Exception('Found more than one computign resource named "{}", cannot continue!'.format(computing_resource_name))

        computing = computing[0]

        # Attach user conf in any
        computing.attach_user_conf(request.user)
        
        return computing
                

    def ls(self, path, user, computing, binds=[]):
        
        # Data container 
        data = []
        
        path = self.sanitize_shell_path(path)
        
        # Prepare command
        # https://askubuntu.com/questions/1116634/ls-command-show-time-only-in-iso-format
        # https://www.howtogeek.com/451022/how-to-use-the-stat-command-on-linux/
        command = self.ssh_command('cd {} && stat --printf=\'%F/%s/%Y/%n\\n\' * .*'.format(path), user, computing)
        
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
                     
            # Check against binds if set            
            if binds:
                if not path == '/':
                    full_path = path + '/' + name
                else:
                    full_path = '/' + name

                show = False
                for bind in binds:
                    if bind.startswith(full_path) or full_path.startswith(bind):
                        show = True
                        break  

            if not binds or (binds and show):
            
                # Define and clean listing path:
                listing_path = '/{}/{}/{}/'.format(computing.name, path, name)
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


    def stat(self, path, user, computing):
        
        path = self.sanitize_shell_path(path)
        
        # Prepare command. See the ls function above for some more info
        command = self.ssh_command('stat --printf=\'%F/%s/%Y/%n\\n\' {}'.format(path), user, computing)
        
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
            


    def delete(self, path, user, computing):

        path = self.sanitize_shell_path(path)

        # Prepare command
        command = self.ssh_command('rm -rf {}'.format(path), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def mkdir(self, path, user, computing):
        
        path = self.sanitize_shell_path(path)
        
        # Prepare command
        command = self.ssh_command('mkdir {}'.format(path), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def cat(self, path, user, computing):
        
        path = self.sanitize_shell_path(path)
        
        # Prepare command
        command = self.ssh_command('cat {}'.format(path), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def rename(self, old, new, user, computing):
        
        old = self.sanitize_shell_path(old)
        new = self.sanitize_shell_path(new)

        # Prepare command
        command = self.ssh_command('mv {} {}'.format(old, new), user, computing)

        logger.critical(command)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def copy(self, source, target, user, computing):

        source = self.sanitize_shell_path(source)
        target = self.sanitize_shell_path(target)

        # Prepare command
        command = self.ssh_command('cp -a {} {}'.format(source, target), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        return out.stdout


    def scp(self, source, target, user, computing, mode='get'):

        source = self.sanitize_shell_path(source)
        target = self.sanitize_shell_path(target)

        # Prepare command
        command = self.scp_command(source, target, user, computing, mode)

        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)


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
                
                # Get computing resources
                computings = list(Computing.objects.filter(user=None)) + list(Computing.objects.filter(user=request.user))
                
                for computing in computings:
                    
                    # For now, we only support SSH-based computing resources
                    if not 'ssh' in computing.access_method:
                        continue
                        
                    # Attach user conf in any
                    computing.attach_user_conf(request.user)
                    
                    data['data'].append({
                                         'id': '/{}/'.format(computing.name),
                                         'type': 'folder',
                                         'attributes':{
                                              'name': computing.name,
                                              'readable': 1,
                                              'writable': 1,
                                              'path': '/{}/'.format(computing.name)                                   
                                          }
                                         })

            else:
                                
                computing = self.get_computing(path, request)
                
                # If we just "entered" a computing resource, filter for its bindings
                # TODO: we can remove this and just always filter agains bind probably...
                if len(path.split('/')) == 3:
                    if computing.user != request.user:
                        binds = computing.sys_conf.get('binds')
                    else:
                        binds = computing.conf.get('binds')
                    
                    if binds:
                        binds = binds.split(',')
                        binds = [bind.split(':')[0] for bind in binds]
                    
                    # Ok, get directoris and files for this folder (always filtering by binds)
                    ls_path = '/'+'/'.join(path.split('/')[2:])
                    data = {'data': self.ls(ls_path, request.user, computing, binds)}
         
                else:
                    # Ok, get directoris and files for this folder:                
                    ls_path = '/'+'/'.join(path.split('/')[2:])
                    data = {'data': self.ls(ls_path, request.user, computing)}


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
            computing = self.get_computing(path, request)
            file_path = '/'+'/'.join(path.split('/')[2:])
            target_path = '/tmp/{}'.format(uuid.uuid4())

            # Get the file
            self.scp(file_path, target_path, request.user, computing, mode='get') 

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
            computing = self.get_computing(path, request)
            file_path = '/'+'/'.join(path.split('/')[2:])

            # Get file contents
            data = self.cat(file_path, request.user, computing)
            
            # Return file contents
            return HttpResponse(data, status=status.HTTP_200_OK)


        elif mode == 'delete':
            logger.debug('Deleting "{}"'.format(path))
            
            # Set support vars
            computing = self.get_computing(path, request)
            path = '/'+'/'.join(path.split('/')[2:])

            # Is it a folder?
            if path.endswith('/'):
                is_folder=True
            else:
                is_folder=False

            # Get file contents
            data = self.delete(path, request.user, computing)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(computing.name, path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'name': path,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(computing.name, path)                            
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
            computing = self.get_computing(path, request)
            path = '/'+'/'.join(path.split('/')[2:]) + name

            # Get file contents
            data = self.mkdir(path, request.user, computing)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(computing.name, path),
                            'type': 'folder',
                            'attributes':{
                                'modified': now_t(), # This is an approximation!
                                'name': name,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(computing.name, path)                            
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
            computing = self.get_computing(old_name_with_path, request)
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
            self.rename(old_name_with_path, new_name_with_path, request.user, computing)
            
            # Add trailing slash for listing
            if is_folder:
                new_name_with_path = new_name_with_path+'/'
            
            # Get new info
            stat = self.stat(new_name_with_path, request.user, computing)

            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(computing.name, new_name_with_path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'modified':   stat['timestamp'],
                                'name': new_name,
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(computing.name, new_name_with_path)                              
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
            computing = self.get_computing(source_name_with_path, request)
            
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
            self.copy(source_name_with_path, target_name_with_path, request.user, computing)

            # Add trailing slash for listing
            if is_folder:
                target_name_with_path = target_name_with_path + '/'

            # Get new info
            stat = self.stat(target_name_with_path, request.user, computing)
 
            # Response data
            data = { 'data': {
                            'id': '/{}{}'.format(computing.name, target_name_with_path),
                            'type': 'folder' if is_folder else 'file',
                            'attributes':{
                                'modified': stat['timestamp'],
                                'name': target_name_with_path.split('/')[-2] if is_folder else target_name_with_path.split('/')[-1],
                                'readable': 1,
                                'writable': 1,
                                'path': '/{}{}'.format(computing.name, target_name_with_path)                            
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
    #    POST 
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
            computing = self.get_computing(path, request)
            path = '/'+'/'.join(path.split('/')[2:])

            # Get the file upload
            file_upload = request.FILES['files']
            
            # generate temporary UUID
            file_uuid = uuid.uuid4()
            
            with open('/tmp/{}'.format(file_uuid), 'wb') as temp_file:
                temp_file.write(file_upload.read())
            
            logger.debug('Wrote "/tmp/{}" for "{}"'.format(file_uuid, file_upload.name))

            # Now copy with scp
            self.scp('/tmp/{}'.format(file_uuid), path + file_upload.name , request.user, computing, mode='put')
        
            # Response data
            data = { 'data': [{
                            'id': '/{}{}{}'.format(computing.name, path, file_upload.name),
                            'type': 'file',
                            'attributes':{
                                'modified': now_t(),  # This is an approximation!
                                'name': file_upload.name,
                                'readable': 1,
                                'size': os.path.getsize('/tmp/{}'.format(file_uuid)), # This is kind of an approximation!
                                'writable': 1,
                                'path': '/{}{}{}'.format(computing.name, path, file_upload.name)                            
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







