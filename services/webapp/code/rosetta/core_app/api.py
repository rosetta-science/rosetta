import re
import logging
from django.http import HttpResponse
from django.utils import timezone
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status, serializers, viewsets
from rest_framework.views import APIView
from .utils import format_exception, send_email, os_shell
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
    

    def prepare_command(self, command, user, computing):

        # Get user key
        user_keys = KeyPair.objects.get(user=user, default=True)

       
        # Get computing host
        computing_host = computing.get_conf_param('host')
        
        # Trick for handling Slurm.. TODO: fix me!
        if not computing_host:
            computing_host = computing.get_conf_param('master')
        
        computing_user = computing.get_conf_param('user')

        if not computing_host:
            raise Exception('No computing host?!')

        if not computing_user:
            raise Exception('No computing user?!')

        # Command
        command = 'ssh -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} {}'.format(user_keys.private_key_file, computing_user, computing_host, command)
        
        return command

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
        computing.attach_user_conf_data(request.user)
        
        return computing
                

    def ls(self, path, user, computing, binds=[]):
        
        # Data container 
        data = []
        
        # Prepare command
        command = self.prepare_command('ls -al /{}'.format(path), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
                            
        # Log        
        #logger.debug('Shell exec output: "{}"'.format(out))
        
        out_lines = out.stdout.split('\n')
        
        for line in out_lines:
            
            # Skip total files summary line at the end
            if line.startswith('total'):
                continue
            
            # Set name
            name = line.split(' ')[-1]
                     
            # Check against binds if set
            if binds:
                full_path = path + '/' + name
                show = False
                for bind in binds:
                    if bind.startswith(full_path) or full_path.startswith(bind):
                        show = True
                        break  

            if not binds or (binds and show):
            
                # File or directory?
                if line.startswith('d'):
                    if line.split(' ')[-1] not in ['.', '..']:
                        data.append({
                                     'id': '/{}/{}/{}/'.format(computing.name, path, name),
                                     'type': 'folder',
                                     'attributes':{
                                          'created':  1616415170,
                                          'modified':   1616415170,
                                          'name': name,
                                          'readable': 1,
                                          'timestamp':   1616415170,
                                          'writable': 1,
                                          'path': '/{}/{}/{}'.format(computing.name, path, name)                                 
                                      }
                                     })
                else:
                    data.append({
                                 'id': '/{}/{}/{}'.format(computing.name, path, name),
                                 'type': 'file',
                                 'attributes':{
                                      'created':  1616415170,
                                      'modified':   1616415170,
                                      'name': name,
                                      'readable': 1,
                                      'timestamp':   1616415170,
                                      'writable': 1,
                                      'path': '/{}/{}/{}'.format(computing.name, path, name)                                
                                  }
                                 })                            
            
            
        return data


    def cat(self, path, user, computing):
        
        # Prepare command
        command = self.prepare_command('cat /{}'.format(path), user, computing)
        
        # Execute_command
        out = os_shell(command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        
        return out.stdout
                 



    def _get(self, request):
        
        mode = request.GET.get('mode', None)
        time = request.GET.get('time', None)
        path = request.GET.get('path', None)
        _ = request.GET.get('_', None)
        
        # Clean for some issues that happen sometimes
        if path:
            cleaner = re.compile('(?:\/)+')
            path = re.sub(cleaner,'/',path)

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

                    # Attach user conf in any
                    computing.attach_user_conf_data(request.user)
                    
                    data['data'].append({
                                         'id': '/{}/'.format(computing.name),
                                         'type': 'folder',
                                         'attributes':{
                                              'created':  1616415170,
                                              'modified':   1616415170,
                                              'name': computing.name,
                                              'readable': 1,
                                              'timestamp':   1616415170,
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
                        binds = computing.get_conf_param('binds', from_sys_only=True )
                    else:
                        binds = computing.get_conf_param('binds')
                    
                    if binds:
                        binds = binds.split(',')
                        binds = [bind.split(':')[0] for bind in binds]
                    
                    # Ok, get directoris and files for this folder (always filtering by binds)
                    ls_path = '/'.join(path.split('/')[2:])
                    data = {'data': self.ls(ls_path, request.user, computing, binds)}
         
                else:
                    # Ok, get directoris and files for this folder:                
                    ls_path = '/'.join(path.split('/')[2:])
                    data = {'data': self.ls(ls_path, request.user, computing)}


        elif mode == 'download':
            logger.debug('Downloading "{}"'.format(path))
            data=''


        elif mode == 'readfile':
            logger.debug('Reading "{}"'.format(path))
            computing = self.get_computing(path, request)
            cat_path = '/'.join(path.split('/')[2:])
            data = self.cat(cat_path, request.user, computing)
        
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
            #logger.debug('Reading "{}"'.format(path))
            #computing = self.get_computing(path, request)
            #cat_path = '/'.join(path.split('/')[2:])
            #data = self.echo(cat_path, request.user, computing)
            return error400('Operation "{}" not supported'.format(mode))
        
        else:
            return error400('Operation "{}" not supported'.format(mode))

        return ok200('ok')







