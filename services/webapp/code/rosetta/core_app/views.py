import os
import uuid
import json
import subprocess
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.db.models import Q
from .models import Profile, LoginToken, Task, TaskStatuses, Container, Computing, KeyPair, ComputingSysConf, ComputingUserConf, Text
from .utils import send_email, format_exception, timezonize, os_shell, booleanize, debug_param, get_task_tunnel_host, get_task_proxy_host, random_username, setup_tunnel_and_proxy, finalize_user_creation
from .decorators import public_view, private_view
from .exceptions import ErrorMessage

# Setup logging
import logging
logger = logging.getLogger(__name__)


# Task cache
_task_cache = {}


@public_view
def login_view(request):

    data = {}

    # If authenticated user reloads the main URL
    if request.method == 'GET' and request.user.is_authenticated:
        return HttpResponseRedirect('/main/')

    # If unauthenticated user tries to log in
    if request.method == 'POST':
        if not request.user.is_authenticated:
            username = request.POST.get('username')
            password = request.POST.get('password')
            # Use Django's machinery to attempt to see if the username/password
            # combination is valid - a User object is returned if it is.

            if "@" in username:
                # Get the username from the email
                try:
                    user = User.objects.get(email=username)
                    username = user.username
                except User.DoesNotExist:
                    if password:
                        raise ErrorMessage('Check email and password')
                    else:
                        # Return here, we don't want to give any hints about existing users
                        data['success'] = 'Ok, if we have your data you will receive a login link by email shortly.'
                        return render(request, 'success.html', {'data': data})

            if password:
                user = authenticate(username=username, password=password)
                if user:
                    login(request, user)
                    return HttpResponseRedirect('/main')
                else:
                    raise ErrorMessage('Check email and password')
            else:

                # If empty password, send mail with login token
                logger.debug('Sending login token via mail to {}'.format(user.email))

                token = uuid.uuid4()

                # Create token or update if existent (and never used)
                try:
                    loginToken = LoginToken.objects.get(user=user)
                except LoginToken.DoesNotExist:
                    LoginToken.objects.create(user=user, token=token)
                else:
                    loginToken.token = token
                    loginToken.save()
                try:
                    send_email(to=user.email, subject='Rosetta login link', text='Hello,\n\nhere is your login link: https://{}/login/?token={}\n\nOnce logged in, you can go to "My Account" and change password (or just keep using the login link feature).\n\nThe Rosetta Team.'.format(settings.ROSETTA_HOST, token))
                except Exception as e:
                    logger.error(format_exception(e))
                    raise ErrorMessage('Something went wrong. Please retry later.')

                # Return here, we don't want to give any hints about existing users
                data['success'] = 'Ok, if we have your data you will receive a login link by email shortly.'
                return render(request, 'success.html', {'data': data})


        else:
            # This should never happen.
            # User tried to log-in while already logged in: log him out and then render the login
            logout(request)

    else:
        # If we are logging in through a token
        token = request.GET.get('token', None)

        if token:

            loginTokens = LoginToken.objects.filter(token=token)

            if not loginTokens:
                raise ErrorMessage('Token not valid or expired')


            if len(loginTokens) > 1:
                raise Exception('Consistency error: more than one user with the same login token ({})'.format(len(loginTokens)))

            # Use the first and only token (todo: use the objects.get and correctly handle its exceptions)
            loginToken = loginTokens[0]

            # Get the user from the table
            user = loginToken.user

            # Set auth backend
            user.backend = 'django.contrib.auth.backends.ModelBackend'

            # Ok, log in the user
            login(request, user)
            loginToken.delete()

            # Now redirect to site
            return HttpResponseRedirect('/main/')


    # All other cases, render the login page again with no other data than title
    return render(request, 'login.html', {'data': data})


@private_view
def logout_view(request):
    logout(request)
    return HttpResponseRedirect('/')


@public_view
def register_view(request):

    data = {}

    # If authenticated user reloads the main URL
    if request.method == 'GET' and request.user.is_authenticated:
        return HttpResponseRedirect('/main/')

    # If unauthenticated register if post
    if request.method == 'POST':
        if not request.user.is_authenticated:
            email    = request.POST.get('email')
            password = request.POST.get('password')
            invitation = request.POST.get('invitation')
            
            if settings.INVITATION_CODE:
                if invitation != settings.INVITATION_CODE:
                    raise ErrorMessage('Wrong invitation code')

            if '@' not in email:
                raise ErrorMessage('Detected invalid email address')
            
            # Register the user
            user = User.objects.create_user(random_username(), password=password, email=email)

            # Is this necessary?
            user.save()
            
            data['user'] = user

            finalize_user_creation(user)

            # Manually set the auth backend for the user
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            
            data['status'] = 'activated'

    # All other cases, render the login page again with no other data than title
    return render(request, 'register.html', {'data': data})



@public_view
def entrypoint(request):
    return HttpResponseRedirect('/main/')



@public_view
def main_view(request):

    # Set data & render
    data = {}
    
    # Get homepage text if any
    try:
        text = Text.objects.get(id='home')
        data['home_text'] = text.content
    except Text.DoesNotExist:
        pass

    return render(request, 'main.html', {'data': data})


#====================
# Account view
#====================

@private_view
def account(request):

    data={}
    data['user'] = request.user
    try:
        profile = Profile.objects.get(user=request.user)
    except Profile.DoesNotExist:
        profile = Profile.objects.create(user=request.user)
    data['profile'] = profile

    # Set values from POST and GET
    edit = request.POST.get('edit', None)
    if not edit:
        edit = request.GET.get('edit', None)
        data['edit'] = edit
    value = request.POST.get('value', None)

    # Fix None
    if value and value.upper() == 'NONE':
        value = None
    if edit and edit.upper() == 'NONE':
        edit = None

    # Set data.default_public_key
    with open(KeyPair.objects.get(user=request.user, default=True).public_key_file) as f:
        data['default_public_key'] = f.read()

    # Edit values
    if edit and value:
        try:
            logger.info('Setting "{}" to "{}"'.format(edit,value))

            # Timezone
            if edit=='timezone' and value:
                # Validate
                timezonize(value)
                profile.timezone = value
                profile.save()

            # Email
            elif edit=='email' and value:
                request.user.email=value
                request.user.save()

            # Password
            elif edit=='password' and value:
                request.user.set_password(value)
                request.user.save()

            # API key
            elif edit=='apikey' and value:
                profile.apikey=value
                profile.save()

            # Plan
            elif edit=='plan' and value:
                profile.plan=value
                profile.save()

            # Generic property
            elif edit and value:
                raise Exception('Attribute to change is not valid')


        except Exception as e:
            logger.error(format_exception(e))
            data['error'] = 'The property "{}" does not exists or the value "{}" is not valid.'.format(edit, value)
            return render(request, 'error.html', {'data': data})

    return render(request, 'account.html', {'data': data})




#=========================
#  Tasks view
#=========================

@private_view
def tasks(request):

    # Init data
    data={}
    data['user']  = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title'] = 'Tasks'

    # Get action if any
    action  = request.GET.get('action', None)
    uuid    = request.GET.get('uuid', None)
    fromlist = request.GET.get('fromlist', False)
    details = booleanize(request.GET.get('details', None))
    

    # Do we have to operate on a specific task?
    if uuid:

        try:
            
            # Get the task (raises if none available including no permission)
            try:
                task = Task.objects.get(user=request.user, uuid=uuid)
            except Task.DoesNotExist:
                raise ErrorMessage('Task does not exists or no access rights')
            data['task'] = task
    
            # Attach user config to computing
            task.computing.attach_user_conf(task.user)

            #  Task actions
            if action=='delete':
                if task.status not in [TaskStatuses.stopped, TaskStatuses.exited]:
                    try:
                        task.computing.manager.stop_task(task)
                    except:
                        pass
                try:
                    # Get the task (raises if none available including no permission)
                    task = Task.objects.get(user=request.user, uuid=uuid)

                    # Re-remove proxy files before deleting the task itself just to be sure
                    try:
                        os.remove('/shared/etc_apache2_sites_enabled/{}.conf'.format(task.uuid))
                    except:
                        pass
                    try:
                        os.remove('/shared/etc_apache2_sites_enabled/{}.htpasswd'.format(task.uuid))
                    except:
                        pass
    
                    # Delete
                    task.delete()
                    
                    # Unset task
                    data['task'] = None    
    
                except Exception as e:
                    data['error'] = 'Error in deleting the task'
                    logger.error('Error in deleting task with uuid="{}": "{}"'.format(uuid, e))
                    return render(request, 'error.html', {'data': data})
                

    
            elif action=='stop': # or delete,a and if delete also remove object
                # Remove proxy files. Do it here or will cause issues when reloading the conf re-using ports of stopped tasks.
                try:
                    os.remove('/shared/etc_apache2_sites_enabled/{}.conf'.format(task.uuid))
                except:
                    pass
                try:
                    os.remove('/shared/etc_apache2_sites_enabled/{}.htpasswd'.format(task.uuid))
                except:
                    pass
                   
                task.computing.manager.stop_task(task)

        except Exception as e:
            data['error'] = 'Error in getting the task or performing the required action'
            logger.error('Error in getting the task with uuid="{}" or performing the required action: "{}"'.format(uuid, e))
            return render(request, 'error.html', {'data': data})

        # Ok, redirect if there was an action
        if action:
            if fromlist:
                return redirect('/tasks')
            else:
                if not task.uuid:
                    # it has just been deleted
                    return redirect('/tasks')
                else:
                    return redirect('/tasks/?uuid={}'.format(task.uuid))


    # Do we have to list all the tasks?
    if not uuid or (uuid and not details):

        # Get all tasks for list
        try:
            tasks = Task.objects.filter(user=request.user).order_by('created') 
        except Exception as e:
            data['error'] = 'Error in getting Tasks info'
            logger.error('Error in getting Virtual Devices: "{}"'.format(e))
            return render(request, 'error.html', {'data': data})
    
        # Update task statuses
        for task in tasks:
            task.update_status()
    
        # Set task and tasks variables
        data['task']  = None   
        data['tasks'] = tasks

    return render(request, 'tasks.html', {'data': data})


#=========================
#  Create Task view
#=========================

@private_view
def create_task(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title']   = 'New Task'

    # Get task container helper function
    def get_task_container(request):
        task_container_uuid = request.POST.get('task_container_uuid', None)
        if not task_container_uuid:
            # At the second step the task uuid is set via a GET request 
            task_container_uuid = request.GET.get('task_container_uuid', None)
        try:
            task_container = Container.objects.get(uuid=task_container_uuid, user=None)
        except Container.DoesNotExist:
            try:
                task_container =  Container.objects.get(uuid=task_container_uuid, user=request.user)
            except Container.DoesNotExist:
                raise Exception('Consistency error, container with uuid "{}" does not exists or user "{}" does not have access rights'.format(task_container_uuid, request.user.email))
        return task_container

    # Get task computing helper function
    def get_task_computing(request):
        task_computing_uuid = request.POST.get('task_computing_uuid', None)
        try:
            task_computing = Computing.objects.get(uuid=task_computing_uuid, user=None)
        except Computing.DoesNotExist:
            try:
                task_computing =  Computing.objects.get(uuid=task_computing_uuid, user=request.user)
            except Computing.DoesNotExist:
                raise Exception('Consistency error, computing with uuid "{}" does not exists or user "{}" does not have access rights'.format(task_computing_uuid, request.user.email))        
        task_computing.attach_user_conf(request.user)
        return task_computing

    # Get task name helper function
    def get_task_name(request):
        task_name = request.POST.get('task_name', None)
        if not task_name:
            raise ErrorMessage('Missing task name')
        return task_name

    # Get step if any, check both POST and GET
    step = request.POST.get('step', None)
    if not step:
        step = request.GET.get('step', None)
    

    # Handle the various steps
    if not step:
        
        # Step one is assumed: chose software container
        return HttpResponseRedirect('/containers/?mode=new_task')
        
    elif step == 'two':
        
        # Get software container
        data['task_container'] = get_task_container(request)

        # List all computing resources 
        data['computings'] = list(Computing.objects.filter(user=None)) + list(Computing.objects.filter(user=request.user))
            
        data['step'] = 'two'
        data['next_step'] = 'three'

    elif step == 'three':

        # Get software container
        data['task_container'] = get_task_container(request)

        # Get computing resource
        data['task_computing'] = get_task_computing(request)
        
        # Generate random auth token        
        data['task_auth_token'] = str(uuid.uuid4())

        # Set current and next step
        data['step'] = 'three'
        data['next_step'] = 'last'


    elif step == 'last':

        # Get software container
        data['task_container'] = get_task_container(request)

        # Get computing resource
        data['task_computing'] = get_task_computing(request)

        # Get task name
        data['task_name'] = get_task_name(request)

        # Generate the task uuid
        task_uuid = str(uuid.uuid4())

        # Create the task object
        task = Task(uuid      = task_uuid,
                    user      = request.user,
                    name      = data['task_name'],
                    status    = TaskStatuses.created,
                    container = data['task_container'],
                    computing = data['task_computing'])

        # Add auth
        task_auth_password = request.POST.get('task_auth_password', None)
        if task_auth_password and not request.user.profile.is_power_user:
            raise ErrorMessage('Sorry, only power users can set a custom task password.')
        task_auth_token = request.POST.get('task_auth_token', None)
        if task_auth_password:
            if task_auth_password != task_auth_token: # Just an extra check probably not much useful
                if not task_auth_password:
                    raise ErrorMessage('No task password set')
                if len(task_auth_password) < 6:
                    raise ErrorMessage('Task password must be at least 6 chars')
                task.password = task_auth_password # Not stored in the ORM model, just a temporary var.
        else:
            task.auth_token = task_auth_token # This is saved on the ORM model
            task.password = task_auth_token # Not stored

        # Any task requires the TCP tunnel for now
        task.requires_tcp_tunnel = True
        
        # Task access method
        access_method = request.POST.get('access_method', None)
        if access_method and access_method != 'auto' and not request.user.profile.is_power_user:
            raise ErrorMessage('Sorry, only power users can set a task access method other than \'auto\'.')
        if access_method == 'auto':
            if task.container.interface_protocol in ['http','https']:
                task.requires_proxy      = True
                task.requires_proxy_auth = True
            else:
                task.requires_proxy      = False
                task.requires_proxy_auth = False                
        elif access_method == 'direct_tunnel':
            task.requires_proxy      = False
            task.requires_proxy_auth = False            
        elif access_method == 'https_proxy':
            task.requires_proxy      = True
            task.requires_proxy_auth = True
        else:
            raise ErrorMessage('Unknown access method "{}"'.format(access_method))

        # Computing options # TODO: This is hardcoded thinking about Slurm and Singularity
        computing_cpus = request.POST.get('computing_cpus', None)
        computing_memory = request.POST.get('computing_memory', None)
        computing_partition = request.POST.get('computing_partition', None)
        extra_binds = request.POST.get('extra_binds', None)
        
        computing_options = {}
        if computing_cpus:
            try:
                int(computing_cpus)
            except:
                raise Exception('Cannot convert computing_cpus to int')
            computing_options['cpus'] = int(computing_cpus)

        if computing_memory:
            computing_options['memory'] = computing_memory

        if computing_partition:
            computing_options['partition'] = computing_partition        
        
        if computing_options:
            task.computing_options = computing_options
                    
        # Attach user config to computing
        task.computing.attach_user_conf(task.user)

        # Set extra binds if any:
        task.extra_binds = extra_binds

        # Save the task before starting it, or the computing manager will not be able to work properly
        task.save()

        # Start the task
        try:
            task.computing.manager.start_task(task)
        except:
            # Delete the task if could not start it
            task.delete()
            
            # ..and re-raise
            raise

        # Ensure proxy conf directory exists
        if not os.path.exists('/shared/etc_apache2_sites_enabled'):
            os.makedirs('/shared/etc_apache2_sites_enabled')
    
        # Add here proxy auth file as we have the password
        if task.requires_proxy_auth:
            out = os_shell('ssh -o StrictHostKeyChecking=no proxy "cd /shared/etc_apache2_sites_enabled/ && htpasswd -bc {}.htpasswd {} {}"'.format(task.uuid, task.user.email, task.password), capture=True)
            if out.exit_code != 0:
                logger.error(out.stderr)
                raise ErrorMessage('Something went wrong when enabling proxy auth')   

        # Set step        
        data['step'] = 'created'


    return render(request, 'create_task.html', {'data': data})


#=========================
#  Task log
#=========================

@private_view
def task_log(request):

    # Init data
    data={}
    data['user']  = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title'] = 'Tasks'

    # Get uuid and refresh if any
    uuid    = request.GET.get('uuid', None)
    refresh = request.GET.get('refresh', None)

    if not uuid:
        return render(request, 'error.html', {'data': 'uuid not set'})

    # Get the task (raises if none available including no permission)
    task = Task.objects.get(user=request.user, uuid=uuid)

    # Set back task and refresh
    data['task']    = task 
    data['refresh'] = refresh

    # Attach user conf in any
    task.computing.attach_user_conf(request.user)
    
    # Get the log
    try:

        data['log'] = task.computing.manager.get_task_log(task)

    except Exception as e:
        data['error'] = 'Error in viewing task log'
        logger.error('Error in viewing task log with uuid="{}": "{}"'.format(uuid, e))
        raise

    return render(request, 'task_log.html', {'data': data})





#=========================
#  Containers
#=========================

@private_view
def containers(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)

    # Get action if any
    uuid   = request.GET.get('uuid', None)
    action = request.GET.get('action', None)

    # Get filter/search if any
    search_text   = request.POST.get('search_text', '')
    search_owner  = request.POST.get('search_owner', 'All')

    # Set back to page data
    data['search_owner'] = search_owner
    data['search_text']  = search_text

    # Are we using this page as first step of a new task?
    data['mode'] = request.GET.get('mode', None)
    if not data['mode']:
        data['mode'] = request.POST.get('mode', None)


    # Do we have to operate on a specific container?
    if uuid:

        try:

            # Get the container (raises if none available including no permission)
            try:
                container = Container.objects.get(uuid=uuid)
            except Container.DoesNotExist:
                raise ErrorMessage('Container does not exists or no access rights')                
            if container.user and container.user != request.user:
                raise ErrorMessage('Container does not exists or no access rights')
            data['container'] = container

            # Container actions
            if action and action=='delete':

                # Delete
                container.delete()
                
                # Redirect
                return HttpResponseRedirect('/containers')

        except Exception as e:
            data['error'] = 'Error in getting the container or performing the required action'
            logger.error('Error in getting the container with uuid="{}" or performing the required action: "{}"'.format(uuid, e))
            return render(request, 'error.html', {'data': data})


    # Get containers (fitered by search term, or all)
    if search_text:
        search_query=(Q(name__icontains=search_text) | Q(description__icontains=search_text) | Q(image__icontains=search_text))
        user_containers = Container.objects.filter(search_query, user=request.user)
        platform_containers = Container.objects.filter(search_query, user=None)
    else:
        user_containers = Container.objects.filter(user=request.user)
        platform_containers = Container.objects.filter(user=None)
    
    # Filter by owner
    if search_owner != 'All':
        if search_owner == 'User':
            platform_containers =[]
        if search_owner == 'Platform':
            user_containers = []

    data['containers'] = list(user_containers) + list(platform_containers)

    return render(request, 'containers.html', {'data': data})



#=========================
#  Add Container view
#=========================

@private_view
def add_container(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title']   = 'Add container'

    # Container name if setting up a new container
    container_name = request.POST.get('container_name', None)

    if container_name:

        # Container description
        container_description = request.POST.get('container_description', None)

        # Container registry
        container_registry = request.POST.get('container_registry', None)

        # Container image
        container_image = request.POST.get('container_image',None)
        
        # Container tag
        container_tag = request.POST.get('container_tag', None)

        # Container architecture
        container_arch = request.POST.get('container_arch')

        # Container operating system
        container_os = request.POST.get('container_os')

        # Container interface port
        container_interface_port = request.POST.get('container_interface_port', None) 
        if container_interface_port:       
            try:
                container_interface_port = int(container_interface_port)
            except:
                raise ErrorMessage('Invalid container port "{}"')
        else:
            container_interface_port = None

        # Container interface protocol 
        container_interface_protocol = request.POST.get('container_interface_protocol', None)

        if container_interface_protocol and not container_interface_protocol in ['http','https']:
            raise ErrorMessage('Sorry, only power users can add custom software containers with interface protocols other than \'http\' or \'https\'.')

        # Container interface transport 
        container_interface_transport = request.POST.get('container_interface_transport')

        # Capabilities
        container_supports_custom_interface_port = request.POST.get('container_supports_custom_interface_port', None)
        if container_supports_custom_interface_port and container_supports_custom_interface_port == 'True':
            container_supports_custom_interface_port = True
        else:
            container_supports_custom_interface_port = False

        container_supports_interface_auth = request.POST.get('container_supports_interface_auth', None)
        if container_supports_interface_auth and container_supports_interface_auth == 'True':
            container_supports_pass_auth = True
        else:
            container_supports_pass_auth = False

        # Log
        #logger.debug('Creating new container object with image="{}", type="{}", registry="{}", ports="{}"'.format(container_image, container_type, container_registry, container_ports))

        # Create
        Container.objects.create(user        = request.user,
                                 name        = container_name,
                                 description = container_description,
                                 registry    = container_registry,
                                 image       = container_image,
                                 tag         = container_tag,
                                 arch        = container_arch,
                                 os          = container_os,
                                 interface_port      = container_interface_port,
                                 interface_protocol  = container_interface_protocol,
                                 interface_transport = container_interface_transport,
                                 supports_custom_interface_port = container_supports_custom_interface_port,
                                 supports_interface_auth = container_supports_pass_auth)
        # Set added switch
        data['added'] = True

    return render(request, 'add_container.html', {'data': data})



#=========================
#  Computings view
#=========================

@private_view
def computings(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title']   = 'Computing resources'
    data['name']    = request.POST.get('name',None)

    # Get action/details if any
    uuid    = request.GET.get('uuid', None)
    action  = request.GET.get('action', None)
    details = booleanize(request.GET.get('details', None))
    computing_uuid = request.GET.get('uuid', None)
    data['details'] = details
    data['action'] = action
    
    if details and computing_uuid:
        try:
            data['computing'] = Computing.objects.get(uuid=computing_uuid, user=request.user)
        except Computing.DoesNotExist:
            data['computing'] = Computing.objects.get(uuid=computing_uuid, user=None)

        # Attach user conf in any
        data['computing'].attach_user_conf(request.user)
            
    
    else:
        data['computings'] = list(Computing.objects.filter(user=None)) + list(Computing.objects.filter(user=request.user))
        
        # Attach user conf in any
        for computing in data['computings']:
            computing.attach_user_conf(request.user)

    return render(request, 'computings.html', {'data': data})


#=========================
#  Add Computing view
#=========================

@private_view
def add_computing(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title']   = 'Add computing'
    data['name']    = request.POST.get('name',None)


    return render(request, 'add_computing.html', {'data': data})



#=========================
# Edit Computing conf view
#=========================

@private_view
def edit_computing_conf(request):

    # Init data
    data={}
    data['user']    = request.user
    data['profile'] = Profile.objects.get(user=request.user)
    data['title']   = 'Add computing'

    # Get computing conf type
    computing_conf_type = request.GET.get('type', request.POST.get('type', None))
    if not computing_conf_type:
        raise Exception('Missing type')
    
    # Get computing uuid
    computing_uuid = request.GET.get('computing_uuid', request.POST.get('computing_uuid', None))
    if not computing_uuid:
        raise Exception('Missing computing_uuid')

    new_conf = request.POST.get('new_conf', None)


    if computing_conf_type == 'sys':
        
        data['type'] = 'sys'
        
        if not request.user.is_superuser:
            raise Exception('Cannot edit sys conf as not superuser')
    
        # Get computing
        try:
            computing = Computing.objects.get(uuid=computing_uuid)
            data['computing'] = computing
        except ComputingSysConf.DoesNotExist:
            raise Exception('Unknown computing "{}"'.format(computing_uuid))
        
        # Get computing conf
        computingSysConf, _ = ComputingSysConf.objects.get_or_create(computing=computing)   
        
        # Edit conf?
        if new_conf:
            new_conf_data = json.loads(new_conf)
            logger.debug('Setting new conf data for sys conf "{}": "{}"'.format(computingSysConf.uuid, new_conf_data))
            computingSysConf.data = new_conf_data
            computingSysConf.save()
            data['saved'] = True
            return HttpResponseRedirect('/computings')


        # Dump conf data for the webpage
        if computingSysConf.data:
            data['computing_conf_data'] = computingSysConf.data
            data['computing_conf_data_json'] = json.dumps(computingSysConf.data)
    
    elif computing_conf_type == 'user':

        data['type'] = 'user'
        
        # Get computing
        try:
            computing = Computing.objects.get(uuid=computing_uuid)
            data['computing'] = computing
        except ComputingUserConf.DoesNotExist:
            raise Exception('Unknown computing "{}"'.format(computing_uuid))

        # Get computing conf
        computingUserConf, _ = ComputingUserConf.objects.get_or_create(computing=computing, user=request.user)

        # Edit conf?
        if new_conf:
            new_conf_data = json.loads(new_conf)
            logger.debug('Setting new conf data for user conf "{}": "{}"'.format(computingUserConf.uuid, new_conf_data))
            computingUserConf.data = new_conf_data
            computingUserConf.save()
            data['saved'] = True
            return HttpResponseRedirect('/computings')
        
        # Dump conf data for the webpage
        if computingUserConf.data:
            data['computing_conf_data'] = computingUserConf.data
            data['computing_conf_data_json'] = json.dumps(computingUserConf.data)

           
    else:
        raise Exception('Unknown computing conf type "{}"'.format(computing_conf_type))
    

    return render(request, 'edit_computing_conf.html', {'data': data})


#=========================
#  Task connect
#=========================

@private_view
def task_connect(request):

    task_uuid = request.GET.get('uuid', None)
    if not task_uuid:
        raise ErrorMessage('Empty task uuid')


    # Get the task     
    #task = Task.objects.get(uuid__startswith=short_uuid)
    task = Task.objects.get(uuid=task_uuid)
    
    if task.user != request.user:
        raise ErrorMessage('You do not have access to this task.')
    
    data ={}
    data['task'] = task
    
    return render(request, 'task_connect.html', {'data': data})


#===========================
# Direct connection handler
#===========================

@private_view
def direct_connection_handler(request, uuid):

    # Get the task     
    #task = Task.objects.get(uuid__startswith=short_uuid)
    task = Task.objects.get(uuid=uuid)

    if task.user != request.user:
        raise ErrorMessage('You do not have access to this task.')

    # First ensure that the tunnel and proxy are set up
    setup_tunnel_and_proxy(task)
    
    # Get task and tunnel proxy host
    task_proxy_host = get_task_proxy_host()
    task_tunnel_host = get_task_tunnel_host()

    # Redirect to the task through the tunnel    
    if task.requires_proxy:
        if task.requires_proxy_auth and task.auth_token:
            user = request.user.email
            password = task.auth_token
            redirect_string = 'https://{}:{}@{}:{}'.format(user, password, task_proxy_host, task.tcp_tunnel_port)        
        else:
            redirect_string = 'https://{}:{}'.format(task_proxy_host, task.tcp_tunnel_port)       
    else:
        redirect_string = '{}://{}:{}'.format(task.container.interface_protocol, task_tunnel_host, task.tcp_tunnel_port)
    
    logger.debug('Task direct connect redirect: "{}"'.format(redirect_string))
    return redirect(redirect_string)
        
    

#===========================
#  Sharable link handler
#===========================

@public_view
def sharable_link_handler(request, short_uuid):

    # Get the task (if the short uuid is not enough an error wil be raised)
    task = Task.objects.get(uuid__startswith=short_uuid)
    
    # First ensure that the tunnel and proxy are set up
    setup_tunnel_and_proxy(task)
    
    # Get task and tunnel proxy host
    task_proxy_host = get_task_proxy_host()
    task_tunnel_host = get_task_tunnel_host()

    # Redirect to the task through the tunnel    
    if task.requires_proxy:
        redirect_string = 'https://{}:{}'.format(task_proxy_host, task.tcp_tunnel_port)       
    else:
        redirect_string = '{}://{}:{}'.format(task.container.interface_protocol, task_tunnel_host, task.tcp_tunnel_port)
    
    logger.debug('Task sharable link connect redirect: "{}"'.format(redirect_string))
    return redirect(redirect_string)


#=========================
#  File manager
#=========================
@public_view
def files_view(request):

    # Set data & render
    data = {}
    return render(request, 'files.html', {'data': data})












