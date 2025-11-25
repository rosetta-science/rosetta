import os
import pytz
import uuid
import json
import requests
import socket
import subprocess
import base64
import time
import datetime
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.contrib.auth.models import User, Group
from django.shortcuts import redirect
from django.db.models import Q
from django.core.exceptions import FieldError
from .models import Profile, LoginToken, Task, TaskStatuses, Container, Computing, KeyPair, Page, Storage
from .utils import send_email, format_exception, timezonize, os_shell, booleanize, get_rosetta_tasks_tunnel_host
from .utils import get_rosetta_tasks_proxy_host, random_username, setup_tunnel_and_proxy, finalize_user_creation
from .utils import sanitize_container_env_vars, get_or_create_container_from_repository
from .decorators import public_view, private_view
from .exceptions import ErrorMessage

# Setup logging
import logging
logger = logging.getLogger(__name__)


# Task cache
_task_cache = {}


#====================
# Support functions
#====================

def get_objects(entity, user):
    if user.is_staff:
        objects = entity.objects.all()
    else:
        objects = entity.objects.filter(Q(user=user) | Q(group__user=user) | Q(group=None))
    return objects

def filter_objects(entity, user, text=None, owner='all'):

    objects = get_objects(entity, user)

    if owner == 'all':
        pass
    elif owner == 'platform':
        objects = objects.filter(group=None)
    elif owner == 'user':
        objects = objects.filter(user=user)
    elif owner.startswith('group:'):
        # Get the group
        group_name = owner[6:]
        group = Group.objects.get(name=group_name)
        if group not in user.groups.all():
            raise PermissionError('Not part of the requested group')
        objects = objects.filter(group=group)

    if text:
        try:
            # Try filtering with description
            objects = objects.filter(
                Q(name__icontains=text) |
                Q(description__icontains=text)
            )
        except FieldError:
            # Fall back on filtering only for the name
            objects = objects.filter(
                Q(name__icontains=text)
            )
    return objects

def get_object(entity, user, uuid):
    object = entity.objects.get(uuid=uuid)
    if  user.is_staff:
        return object
    if object.user == user or object.group is None or object in object.group.user_set.all():
        return object
    else:
        raise PermissionError('Cannot get as not staff, user or part of same group')

def get_object_for_edit(entity, user, uuid):
    object = entity.objects.get(uuid=uuid)
    if  user.is_staff:
        return object
    if object.user == user:
        return object
    else:
        raise PermissionError('Cannot get as not staff, user or part of same group')

def get_group(user, id):
    retrieved_group = Group.objects.get(id=id)
    if not user.is_staff and retrieved_group not in user.groups.all():
        raise PermissionError('Not staff not part of the requested group')
    return retrieved_group

def get_user(user, id):
    retrieved_user = User.objects.get(id=id)
    if not user.is_staff and retrieved_user != user:
        raise PermissionError('Not staff nor the same user')
    return retrieved_user



# Container family support class
class ContainerFamily(object):

    def __init__(self, id, name, registry, image_name):
        self.id = id
        self.name = name
        self.registry = registry
        self.image_name = image_name
        self.description = None
        self.members = []
        self.all_archs = []
        self.container_by_tags_by_arch = {}

    def add(self, container):
        self.members.append(container)

        container_image_arch = container.image_arch

        # Handle None arch
        if container_image_arch is None:
            container_image_arch = ''

        if not self.description:
            self.description = container.description

        if not container_image_arch in self.all_archs:
            self.all_archs.append(container_image_arch)

        if not container_image_arch in self.container_by_tags_by_arch:
            self.container_by_tags_by_arch[container_image_arch]={}
        self.container_by_tags_by_arch[container_image_arch][container.image_tag] = container


    def finalize(self, desc=True):

        # Order versions
        for arch in self.container_by_tags_by_arch:
            latest = self.container_by_tags_by_arch[arch].pop('latest', None)
            container_by_tags_ordered = dict(sorted(self.container_by_tags_by_arch[arch].items(), reverse=desc))
            if latest:
                if desc:
                    self.container_by_tags_by_arch[arch] = {'latest': latest}
                    self.container_by_tags_by_arch[arch].update(container_by_tags_ordered)
                else:
                    self.container_by_tags_by_arch[arch] = container_by_tags_ordered
                    self.container_by_tags_by_arch[arch].update({'latest': latest})
            else:
                self.container_by_tags_by_arch[arch] = container_by_tags_ordered

        # Order archs
        self.container_by_tags_by_arch = dict(sorted(self.container_by_tags_by_arch.items(), reverse=False))


    @ property
    def color(self):
        try:
            return self.members[0].color
        except IndexError:
            return '#000000'



#====================
#  Page views
#====================

@public_view
def login_view(request):

    data = {}

    # Set post login page
    post_login_page = request.COOKIES.get('post_login_redirect')
    if post_login_page is None:
        post_login_page = '/main'

    # If authenticated user reloads the main URL
    if request.method == 'GET' and request.user.is_authenticated:
        response = HttpResponseRedirect(post_login_page)
        response.delete_cookie('post_login_redirect')
        return response
    else:
        # If local auth disabled, just redirect to OIDC
        if settings.DISABLE_LOCAL_AUTH:
            return HttpResponseRedirect('/oidc/authenticate/')

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
                    if user.profile.auth != 'local':
                        # This actually hides that the user cannot be authenticated using the local auth.
                        raise ErrorMessage('Check email and password')
                    login(request, user)
                    response = HttpResponseRedirect(post_login_page)
                    response.delete_cookie('post_login_redirect')
                    return response
                else:
                    raise ErrorMessage('Check email and password')
            else:

                # If empty password and local auth, send mail with login token
                if user.profile.auth == 'local':

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
                        send_email(to=user.email, subject='Rosetta login link', text='Hello,\n\nhere is your login link: https://{}/login/?token={}\n\nOnce logged in, you can go to "My Account" and change password (or just keep using the login link feature).\n\nThe Rosetta platform.'.format(settings.ROSETTA_HOST, token))
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
            response = HttpResponseRedirect(post_login_page)
            response.delete_cookie('post_login_redirect')
            return response

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

    # Init data
    data = {}

    # Get custom home page if any
    try:
        page = Page.objects.get(id='main')
        data['page'] = page
    except Page.DoesNotExist:
        pass

    return render(request, 'main.html', {'data': data})


@public_view
def page_view(request, page_id):

    # Init data
    data = {}

    # Get the page
    try:
        page = Page.objects.get(id=page_id)
        data['page'] = page
    except Page.DoesNotExist:
        return HttpResponseNotFound('Page not found')

    return render(request, 'page.html', {'data': data})



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

    # Add computings (for extra confs)
    if request.user.profile.extra_confs:
        data['computings'] = list(Computing.objects.filter(group=None)) + list(Computing.objects.filter(group__user=request.user))

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
                # If no local auth, you should never get here
                if request.user.profile.auth != 'local':
                    raise ErrorMessage('Cannot change password using an external authentication service')
                request.user.email=value
                request.user.save()

            # Password
            elif edit=='password' and value:
                # If no local auth, you should never get here
                if request.user.profile.auth != 'local':
                    raise ErrorMessage('Cannot change password using an external authentication service')
                request.user.set_password(value)
                request.user.save()

            # Generic property
            elif edit and value:
                raise Exception('Attribute to change is not valid')


        except Exception as e:
            logger.error(format_exception(e))
            data['error'] = 'The property "{}" does not exists or the value "{}" is not valid.'.format(edit, value)
            return render(request, 'error.html', {'data': data})

    # Lastly, do we have to remove an extra conf?

    delete_extra_conf_uuid = request.GET.get('delete_extra_conf_uuid', None)
    if delete_extra_conf_uuid:
        #logger.debug('Deleting extra conf "{}"'.format(delete_extra_conf_uuid))
        new_extra_confs = {}
        for extra_conf_uuid in profile.extra_confs:
            if extra_conf_uuid != delete_extra_conf_uuid:
                new_extra_confs[extra_conf_uuid] = profile.extra_confs[extra_conf_uuid]
        profile.extra_confs = new_extra_confs
        profile.save()
        return redirect('/account')



    return render(request, 'account.html', {'data': data})



#=========================
#  Tasks view
#=========================

@private_view
def tasks(request):

    # Get data
    action  = request.GET.get('action', None)
    uuid    = request.GET.get('uuid', None)
    filter_text = request.POST.get('filter_text', '')
    filter_status = request.POST.get('filter_status', 'all')
    fromlist = booleanize(request.GET.get('fromlist', False))

    # Set data
    data={}
    data['user']  = request.user
    data['filter_text'] = filter_text
    data['filter_status'] = filter_status
    task_statuses = []
    for var in vars(TaskStatuses):
        if var.startswith('_'):
            continue
        task_statuses.append(var)
    data['task_statuses'] = sorted(task_statuses)

    # Get the task if a specific uuid is given, or get them all, possibly filtering
    if uuid:
        task = Task.objects.get(user=request.user, uuid=uuid)
        data['task'] = task

    else:
        tasks = Task.objects.filter(user=request.user).order_by('created')

        if filter_status and filter_status != 'all':
            tasks = tasks.filter(status=filter_status)

        if filter_text:
            tasks = tasks.filter(name__icontains=filter_text)

        # Update task statuses
        for task in tasks:
            task.update_status()

        # Set task and tasks variables
        data['tasks'] = tasks

    # Handle delete action
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

        return redirect('/tasks/')

    # Handle stop action
    elif action=='stop':
        try:
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

        if fromlist:
            return redirect('/tasks')
        else:
            return redirect('/tasks/?uuid={}'.format(task.uuid))

    return render(request, 'tasks.html', {'data': data})


#=========================
#  New task
#=========================

@private_view
def new_task(request):

    # Init data
    data={}
    data['user']    = request.user

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
            task_computing = Computing.objects.get(uuid=task_computing_uuid, group=None)
        except Computing.DoesNotExist:
            try:
                task_computing =  Computing.objects.get(uuid=task_computing_uuid, group__user=request.user)
            except Computing.DoesNotExist:
                raise Exception('Consistency error, computing with uuid "{}" does not exists or user "{}" does not have access rights'.format(task_computing_uuid, request.user.email))
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
        return HttpResponseRedirect('/software/?mode=new_task')

    elif step == 'two':

        # Get software container and arch
        data['task_container'] = get_task_container(request)

        # List all computing resources
        data['computings'] = list(Computing.objects.filter(group=None)) + list(Computing.objects.filter(group__user=request.user))

        data['step'] = 'two'
        data['next_step'] = 'three'

    elif step == 'three':

        # Get software container and arch
        data['task_container'] = get_task_container(request)

        # Get computing resource
        data['task_computing'] = get_task_computing(request)

        # Check that container required architecture is compatible with the computing resource
        # TODO: support setting the container engine/engine when creating the task
        # TODO: refactor and unroll this code
        if data['task_computing'].supported_archs is None: data['task_computing'].supported_archs=[]
        if data['task_computing'].emulated_archs is None: data['task_computing'].emulated_archs={}
        data['arch_emulation'] = False

        if data['task_container'].image_arch:
            if (data['task_container'].image_arch != data['task_computing'].arch) and (data['task_container'].image_arch not in data['task_computing'].supported_archs):

                # Does container engines/engines support emulated archs?
                if data['task_computing'].emulated_archs:

                    # For now by default our container engine is the first one
                    container_engine = data['task_computing'].container_engines[0]

                    # Check for emulation against the engine
                    if container_engine in data['task_computing'].emulated_archs and data['task_container'].image_arch in data['task_computing'].emulated_archs[container_engine]:
                        data['arch_emulation'] = True

                    # Check for emulation against the engine
                    def get_engines(container_engine):
                        if not '[' in container_engine:
                            return None
                        else:
                            container_engines = container_engine.split('[')[1].replace(']','').split(',')
                            return container_engines

                    for container_engine in get_engines(container_engine):
                        if container_engine in data['task_computing'].emulated_archs and data['task_container'].image_arch in data['task_computing'].emulated_archs[container_engine]:
                            data['arch_emulation'] = True

                    if not data['arch_emulation']:
                        raise ErrorMessage('This computing resource does not support architecture \'{}\' nor as native or emulated'.format(data['task_container'].image_arch))

                else:
                    raise ErrorMessage('This computing resource does not support architecture \'{}\' nor as native or emulated'.format(data['task_container'].image_arch))

        else:
            data['arch_auto_selection'] = True
            #raise ErrorMessage('Auto selecting architectures is not supported yet')

        # Generate random auth token
        data['task_auth_token'] = str(uuid.uuid4())

        # Set current and next step
        data['step'] = 'three'
        data['next_step'] = 'last'


    elif step == 'last':

        # Get software container and arch
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
        access_method = request.POST.get('access_method', 'auto')
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

        # Computing options
        computing_options = {}

        # Container engine if any set
        container_engine = request.POST.get('container_engine', None)
        if container_engine:
            if not container_engine in data['task_computing'].container_engines:
                raise ErrorMessage('Unknown container engine "{}"'.format(container_engine))
            computing_options['container_engine'] = container_engine

        # CPUs, memory and partition if set
        computing_cpus = request.POST.get('computing_cpus', None)
        computing_memory = request.POST.get('computing_memory', None)
        computing_partition = request.POST.get('computing_partition', None)

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


    return render(request, 'new_task.html', {'data': data})


#=========================
#  Task log
#=========================

@private_view
def task_log(request):

    # Init data
    data={}
    data['user']  = request.user

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

    # Get the log
    try:

        data['log'] = task.computing.manager.get_task_log(task)

    except Exception as e:
        data['error'] = 'Error in viewing task log'
        logger.error('Error in viewing task log with uuid="{}": "{}"'.format(uuid, e))
        raise

    return render(request, 'task_log.html', {'data': data})



#=========================
#  Software containers
#=========================

@private_view
def software(request):

    # Get data
    uuid = request.GET.get('uuid', None)
    family_id = request.GET.get('container_family_id', None)
    action = request.GET.get('action', None)
    filter_text = request.POST.get('filter_text', '')
    filter_owner = request.POST.get('filter_owner', 'all')
    details = booleanize(request.GET.get('details', False))

    # Set data
    data = {}
    data['user'] = request.user
    data['filter_text'] = filter_text
    data['filter_owner'] = filter_owner
    data['details'] = details

    # Get the container if a specific uuid is given, or get them all, possibly filtering
    if uuid:
        container = get_object(Container, user=request.user, uuid=uuid)
        data['container'] = container
    else:
        containers = filter_objects(Container, user=request.user, text=filter_text, owner=filter_owner)
        # Handle operating on a container family: decode data from the family id and kepe only these containers
        if family_id:
            container_name, container_registry, container_image_name = base64.b64decode(family_id.encode('utf8')).decode('utf8').split('\t')
            containers = containers.filter(name=container_name, registry=container_registry, image_name=container_image_name)
        data['containers'] = containers

    # Are we using this page as first step of a new task?
    data['mode'] = request.GET.get('mode', None)
    if not data['mode']:
        data['mode'] = request.POST.get('mode', None)

    # Handle delete action
    if action == 'delete':
        container = get_object_for_edit(Container, request.user, uuid)
        container.delete()
        return redirect('/software/')

    # Handle duplicate action
    if action == 'duplicate':
        if not request.user.is_staff:
            if container.user != request.user:
                raise ErrorMessage('Can duplicate only software containers owned by the user')
        new_container = Container(
            user=container.user,
            name='{} (copy)'.format(container.name),
            description=container.description,
            registry=container.registry,
            image_name=container.image_name,
            image_tag=container.image_tag,
            image_arch=container.image_arch,
            image_os=container.image_os,
            image_digest=container.image_digest,
            interface_port=container.interface_port,
            interface_protocol=container.interface_protocol,
            interface_transport=container.interface_transport,
            supports_custom_interface_port=container.supports_custom_interface_port,
            supports_interface_auth=container.supports_interface_auth,
            interface_auth_user=container.interface_auth_user,
            disable_http_basicauth_embedding=container.disable_http_basicauth_embedding,
            env_vars=container.env_vars,
            group=container.group
        )
        new_container.save()
        return redirect('/edit_software/?uuid={}&created=True'.format(new_container.uuid))

    if 'containers' in data:

        # Init container families 
        data['container_families'] = {}

        # Populate container families by merging containers with the same name, registry and image name
        for container in data['containers']:
            if container.family_id not in data['container_families']:
                data['container_families'][container.family_id] = ContainerFamily(container.family_id, container.name, container.registry, container.image_name)
            data['container_families'][container.family_id].add(container)

        # Finalize the families
        for family_id in data['container_families']:
            data['container_families'][family_id].finalize()

    return render(request, 'software.html', {'data': data})


@private_view
def add_software(request):

    # Get data
    new_container_from = request.GET.get('new_container_from', 'registry')

    # Set data
    data = {}
    data['user'] = request.user
    data['new_container_from'] = new_container_from # To handle the UI switch 
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':

        new_container_from = request.POST.get('new_container_from', None)

        if new_container_from == 'repository':
            container_name = request.POST.get('container_name', None)
            container_description = request.POST.get('container_description', None)
            repository_url = request.POST.get('repository_url', None)
            repository_tag = request.POST.get('repository_tag', 'HEAD')
            return HttpResponseRedirect('/import_repository/?repository_url={}&repository_tag={}&container_name={}&container_description={}'.format(repository_url,repository_tag,container_name,container_description))

        elif new_container_from == 'registry':

            container = Container()
            container.name = request.POST.get('container_name', None)
            container.description = request.POST.get('container_description', None)
            container.registry = request.POST.get('container_registry', None)
            container.image_name = request.POST.get('container_image_name',None)
            container.image_tag = request.POST.get('container_image_tag', None)
            container.image_arch = request.POST.get('container_image_arch', None)
            container.image_os = request.POST.get('container_image_os', None)
            container.image_digest = request.POST.get('container_image_digest', None)
            container.interface_transport = request.POST.get('container_interface_transport')

            # Set fields requiring validation
            container_interface_port = request.POST.get('container_interface_port', None)
            if container_interface_port:
                try:
                    container.interface_port = int(container_interface_port)
                except:
                    raise ErrorMessage('Invalid port "{}"')
            else:
                container.interface_port = None

            container.interface_protocol = request.POST.get('container_interface_protocol', None)
            if container.interface_protocol and not container.interface_protocol in ['http','https']:
                if not request.user.is_staff:
                    raise ErrorMessage('Sorry, only power users can add custom software containers with interface protocols other than \'http\' or \'https\'.')

            # Set booleans
            container_supports_custom_interface_port = request.POST.get('container_supports_custom_interface_port', None)
            if container_supports_custom_interface_port and container_supports_custom_interface_port == 'True':
                container.supports_custom_interface_port = True
            else:
                container.supports_custom_interface_port = False

            container_supports_interface_auth = request.POST.get('container_supports_interface_auth', None)
            if container_supports_interface_auth and container_supports_interface_auth == 'True':
                container.supports_interface_auth = True
            else:
                container.supports_interface_auth = False

            container_disable_http_basicauth_embedding = request.POST.get('container_disable_http_basicauth_embedding', None)
            if container_disable_http_basicauth_embedding and container_disable_http_basicauth_embedding == 'True':
                container.disable_http_basicauth_embedding = True
            else:
                container.disable_http_basicauth_embedding = False

            # Set environment variables
            container_env_vars = request.POST.get('container_env_vars', None)
            if container_env_vars:
                container_env_vars = sanitize_container_env_vars(json.loads(container_env_vars))

            # Set the group
            group_id = request.POST.get('group_id', None)
            if group_id:
                container.group = get_group(request.user, id=group_id)
            else:
                if request.user.is_staff:
                    container.group = None
                else:
                    raise PermissionError('Only admins can create platform containers')

            # Save & redirect
            container.save()
            return redirect('/edit_software/?uuid={}&created=True'.format(container.uuid))

        else:
            raise Exception('Unknown new container mode "{}"'.format(new_container_from))

    return render(request, 'add_software.html', {'data': data})


@private_view
def edit_software(request):

    # Get data
    created = request.GET.get('created', False)
    saved = request.GET.get('saved', False)
    container_uuid = request.GET.get('uuid', None)
    container = get_object_for_edit(Container, user=request.user, uuid=container_uuid)

    # Set data
    data = {}
    data['user'] = request.user
    data['created'] = created
    data['saved'] = saved
    data['container'] = container
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':

        container.name = request.POST.get('container_name', None)
        container.description = request.POST.get('container_description', None)
        container.registry = request.POST.get('container_registry', None)
        container.image_name = request.POST.get('container_image_name',None)
        container.image_tag = request.POST.get('container_image_tag', None)
        container.image_arch = request.POST.get('container_image_arch', None)
        container.image_os = request.POST.get('container_image_os', None)
        container.image_digest = request.POST.get('container_image_digest', None)
        container.interface_transport = request.POST.get('container_interface_transport')

        # Set fields requiring validation
        container_interface_port = request.POST.get('container_interface_port', None)
        if container_interface_port:
            try:
                container.interface_port = int(container_interface_port)
            except:
                raise ErrorMessage('Invalid port "{}"')
        else:
            container.interface_port = None

        container.interface_protocol = request.POST.get('container_interface_protocol', None)
        if container.interface_protocol and not container.interface_protocol in ['http','https']:
            if not request.user.is_staff:
                raise ErrorMessage('Sorry, only power users can add custom software containers with interface protocols other than \'http\' or \'https\'.')

        # Set booleans
        container_supports_custom_interface_port = request.POST.get('container_supports_custom_interface_port', None)
        if container_supports_custom_interface_port and container_supports_custom_interface_port == 'True':
            container.supports_custom_interface_port = True
        else:
            container.supports_custom_interface_port = False

        container_supports_interface_auth = request.POST.get('container_supports_interface_auth', None)
        if container_supports_interface_auth and container_supports_interface_auth == 'True':
            container.supports_interface_auth = True
        else:
            container.supports_interface_auth = False

        container_disable_http_basicauth_embedding = request.POST.get('container_disable_http_basicauth_embedding', None)
        if container_disable_http_basicauth_embedding and container_disable_http_basicauth_embedding == 'True':
            container.disable_http_basicauth_embedding = True
        else:
            container.disable_http_basicauth_embedding = False

        # Set environment variables
        container_env_vars = request.POST.get('container_env_vars', None)
        if container_env_vars:
            container_env_vars = sanitize_container_env_vars(json.loads(container_env_vars))

        # Set the group
        group_id = request.POST.get('group_id', None)
        if group_id:
            container.group = get_group(request.user, id=group_id)
        else:
            if request.user.is_staff:
                container.group = None
            else:
                raise PermissionError('Only admins can create platform containers')

        # Save & redirect
        container.save()
        return redirect('/edit_software/?uuid={}&saved=True'.format(container.uuid))

    return render(request, 'edit_software.html', {'data': data})


#=========================
#  Computing resources
#=========================

@private_view
def computing(request):

    # Get data
    user = request.user
    uuid = request.GET.get('uuid', None)
    action = request.GET.get('action', None)
    filter_text = request.POST.get('filter_text', '')
    filter_owner = request.POST.get('filter_owner', 'all')

    # Set in the page
    data = {}
    data['user'] = user
    data['filter_text'] = filter_text
    data['filter_owner'] = filter_owner

    # Get the computing if a specific uuid is given, or get them all, possibly filtering
    if uuid:
        computing = get_object(Computing, user=user, uuid=uuid)
        data['computing'] = computing
    else:
        computings = filter_objects(Computing, user=user, text=filter_text, owner=filter_owner)
        data['computings'] = computings

    # Handle delete action
    if action == 'delete':
        computing = get_object_for_edit(Computing, user, uuid)
        computing.delete()
        return redirect('/computing/')

    # Handle duplicate action
    if action == 'duplicate':
        if not user.is_staff:
            if computing.user != user:
                raise ErrorMessage('Can duplicate only computing resources owned by the user')
        new_computing = Computing(
            name='{} (copy)'.format(computing.name),
            description=computing.description,
            type=computing.type,
            arch=computing.arch,
            access_mode=computing.access_mode,
            auth_mode=computing.auth_mode,
            wms=computing.wms,
            container_engines=computing.container_engines,
            supported_archs=computing.supported_archs,
            emulated_archs=computing.emulated_archs,
            conf=computing.conf,
            group=computing.group
        )
        new_computing.save()
        return redirect('/edit_computing/?uuid={}&saved=True'.format(new_computing.uuid))

    return render(request, 'computing.html', {'data': data})


@private_view
def add_computing(request):

    # Set data
    data = {}
    data['user'] = request.user
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':
        computing = Computing()
        computing.name = request.POST.get('name', None)
        computing.description = request.POST.get('description', None)
        computing.type = request.POST.get('type', None)
        computing.arch = request.POST.get('arch', None)
        computing.access_mode = request.POST.get('access_mode', None)
        computing.auth_mode = request.POST.get('auth_mode', None)
        computing.wms = request.POST.get('wms', None)

        # Set the user
        user_id = request.POST.get('user_id', None)
        if user_id:
            computing.user = get_user(request.user, id=user_id)
        else:
            computing.user = None

        # Set the group
        group_id = request.POST.get('group_id', None)
        if group_id:
            computing.group = get_group(request.user, id=group_id)
        else:
            if request.user.is_staff:
                computing.group = None

        # Set json fields
        container_engines = request.POST.get('container_engines', None)
        if container_engines:
            computing.container_engines = json.loads(container_engines)
        else:
            computing.container_engines = None

        supported_archs = request.POST.get('supported_archs', None)
        if supported_archs:
            computing.supported_archs = json.loads(supported_archs)
        else:
            computing.supported_archs = None

        emulated_archs = request.POST.get('emulated_archs', None)
        if emulated_archs:
            computing.emulated_archs = json.loads(emulated_archs)
        else:
            computing.emulated_archs = None

        # Set the conf
        conf = request.POST.get('conf', None)
        if conf:
            computing.conf = json.loads(conf)
        else:
            computing.conf = None

        # Save & redirect
        computing.save()
        return redirect('/edit_computing/?uuid={}&created=True'.format(computing.uuid))

    return render(request, 'add_computing.html', {'data': data})


@private_view
def edit_computing(request):

    # Get data
    user = request.user
    created = request.GET.get('created', False)
    saved = request.GET.get('saved', False)
    computing_uuid = request.GET.get('uuid', None)
    computing = get_object_for_edit(Computing, user=user, uuid=computing_uuid)

    # Set in the page
    data = {}
    data['user'] = user
    data['created'] = created
    data['saved'] = saved
    data['computing'] = computing
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':
        computing.name = request.POST.get('name', computing.name)
        computing.description = request.POST.get('description', computing.description)
        computing.type = request.POST.get('type', computing.type)
        computing.arch = request.POST.get('arch', computing.arch)
        computing.access_mode = request.POST.get('access_mode', computing.access_mode)
        computing.auth_mode = request.POST.get('auth_mode', computing.auth_mode)
        computing.wms = request.POST.get('wms', computing.wms)

        # Update the user
        user_id = request.POST.get('user_id', None)
        if user_id:
            computing.user = get_user(request.user, id=user_id)
        else:
            computing.user = None

        # Update the group
        group_id = request.POST.get('group_id', None)
        if group_id:
            computing.group = get_group(request.user, id=group_id)
        else:
            computing.group = None

        # Set json fields
        container_engines = request.POST.get('container_engines', None)
        if container_engines:
            computing.container_engines = json.loads(container_engines)
        else:
            computing.container_engines = None

        supported_archs = request.POST.get('supported_archs', None)
        if supported_archs:
            computing.supported_archs = json.loads(supported_archs)
        else:
            computing.supported_archs = None

        emulated_archs = request.POST.get('emulated_archs', None)
        if emulated_archs:
            computing.emulated_archs = json.loads(emulated_archs)
        else:
            computing.emulated_archs = None

        # Update the conf
        conf = request.POST.get('conf', None)
        if conf:
            computing.conf = json.loads(conf)
        else:
            computing.conf = None

        # Save & redirect
        computing.save()
        return redirect('/edit_computing/?uuid={}&saved=True'.format(computing.uuid))

    return render(request, 'edit_computing.html', {'data': data})


#=========================
#  Storage
#=========================

@private_view
def storage(request):

    # Get data
    manage  = request.GET.get('manage', False) # Mainly a UI switch, actually
    uuid = request.GET.get('uuid', None)
    action = request.GET.get('action', None)
    filter_text = request.POST.get('filter_text', '')
    filter_owner = request.POST.get('filter_owner', 'all')

    # Set in the page
    data = {}
    data['user'] = request.user
    data['manage'] = manage
    data['filter_text'] = filter_text
    data['filter_owner'] = filter_owner

    # Get the storage if a specific uuid is given, or get them all, possibly filtering
    if uuid:
        storage = get_object(Storage, user=request.user, uuid=uuid)
        data['storage'] = storage
    else:
        storages = filter_objects(Storage, user=request.user, text=filter_text, owner=filter_owner)
        data['storages'] = storages

    # Handle delete action
    if action == 'delete':
        storage = get_object_for_edit(Storage, request.user, uuid)
        storage.delete()
        return redirect('/storage/?manage=True')

    # Handle duplicate action
    if action == 'duplicate':
        if not request.user.is_staff:
            if storage.user != request.user:
                raise ErrorMessage('Can duplicate only storages owned by the user')
        new_storage = Storage(
            name='{} (copy)'.format(storage.name),
            type=storage.type,
            access_mode=storage.access_mode,
            auth_mode=storage.auth_mode,
            base_path=storage.base_path,
            bind_path=storage.bind_path,
            read_only=storage.read_only,
            browsable=storage.browsable,
            group=storage.group,
            user=request.user, # This always changes, set to the user who duplicates
            computing=storage.computing,
            access_through_computing=storage.access_through_computing,
            conf=storage.conf
        )
        new_storage.save()
        return redirect('/edit_storage/?uuid={}&created=True'.format(new_storage.uuid))

    return render(request, 'storage.html', {'data': data})


@private_view
def add_storage(request):

    # Set data
    data = {}
    data['user'] = request.user
    if request.user.is_staff:
        data['computings'] = Computing.objects.all()
    else:
        data['computings'] = Computing.objects.filter(user=request.user)
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':
        storage = Storage()
        storage.name = request.POST.get('name', None)
        storage.type = request.POST.get('type', None)
        storage.access_mode = request.POST.get('access_mode', None)
        storage.auth_mode = request.POST.get('auth_mode', None)
        storage.base_path = request.POST.get('base_path', None)
        storage.bind_path = request.POST.get('bind_path', None)
        storage.read_only = bool(request.POST.get('read_only', False))
        storage.browsable = bool(request.POST.get('browsable', False))
        storage.access_through_computing = bool(request.POST.get('access_through_computing', False))

        # Set the computing resource
        computing_uuid = request.POST.get('computing_uuid', None)
        if computing_uuid:
            storage.computing = get_object(Computing, user=request.user, uuid=computing_uuid)
        else:
            storage.computing = None

        # Set the user
        user_id = request.POST.get('user_id', None)
        if user_id:
            storage.user = get_user(request.user, id=user_id)
        else:
            storage.user = None

        # Set the group
        group_id = request.POST.get('group_id', None)
        if group_id:
            storage.group = get_group(request.user, id=group_id)
        else:
            if request.user.is_staff:
                storage.group = None

        # Set the conf
        conf = request.POST.get('conf', None)
        if conf:
            storage.conf = json.loads(conf)
        else:
            storage.conf = None

        # Save & redirect
        storage.save()
        return redirect('/edit_storage/?uuid={}&created=True'.format(storage.uuid))

    return render(request, 'add_storage.html', {'data': data})


@private_view
def edit_storage(request):

    # Get data
    created = request.GET.get('created', False)
    saved = request.GET.get('saved', False)
    storage_uuid = request.GET.get('uuid', None)
    storage = get_object_for_edit(Storage, user=request.user, uuid=storage_uuid)

    # Set data
    data = {}
    data['user'] = request.user
    data['created'] = created
    data['saved'] = saved
    data['storage'] = storage
    if request.user.is_staff:
        data['computings'] = Computing.objects.all()
    else:
        data['computings'] = Computing.objects.filter(user=request.user)
    if request.user.is_staff:
        data['groups'] = Group.objects.all()
    else:
        data['groups'] = request.user.groups.all()

    if request.method == 'POST':
        storage.name = request.POST.get('name', storage.name)
        storage.type = request.POST.get('type', storage.type)
        storage.access_mode = request.POST.get('access_mode', storage.access_mode)
        storage.auth_mode = request.POST.get('auth_mode', storage.auth_mode)
        storage.base_path = request.POST.get('base_path', storage.base_path)
        storage.bind_path = request.POST.get('bind_path', storage.bind_path)
        storage.read_only = bool(request.POST.get('read_only', False))
        storage.browsable = bool(request.POST.get('browsable', False))
        storage.access_through_computing = bool(request.POST.get('access_through_computing', False))

        # Update the computing resource
        computing_uuid = request.POST.get('computing_uuid', None)
        if computing_uuid:
            storage.computing = get_object(Computing, user=request.user, uuid=computing_uuid)
        else:
            storage.computing = None

        # Update the user
        user_id = request.POST.get('user_id', None)
        if user_id:
            storage.user = get_user(request.user, id=user_id)
        else:
            storage.user = None

        # Update the group
        group_id = request.POST.get('group_id', None)
        if group_id:
            storage.group = get_group(request.user, id=group_id)
        else:
            if request.user.is_staff:
                storage.group = None

        # Update the conf
        conf = request.POST.get('conf', None)
        if conf:
            storage.conf = json.loads(conf)
        else:
            storage.conf = None

        # Save & redirect
        storage.save()
        return redirect('/edit_storage/?uuid={}&saved=True'.format(storage.uuid))

    return render(request, 'edit_storage.html', {'data': data})


#=========================
#  Add profile conf
#=========================

@private_view
def add_profile_conf(request):

    # Init data
    data={}
    data['user']    = request.user

    # Set conf types we can add
    data['conf_types'] = ['computing_user'] #,'computing_custom_binds']

    # Process adding the new conf
    conf_type = request.POST.get('conf_type', None)
    if conf_type:
        data['conf_type'] = conf_type
        if conf_type in ['computing_user']:
            computing_uuid = request.POST.get('computing_uuid', None)
            if computing_uuid:
                try:
                    computing = Computing.objects.get(uuid=computing_uuid, group__user=request.user)
                except Computing.DoesNotExist:
                    computing = Computing.objects.get(uuid=computing_uuid, group=None)
                data['computing'] = computing
                data['last_step'] = True
                value = request.POST.get('value', None)
                if value:
                    request.user.profile.add_extra_conf(conf_type=conf_type, object=computing, value=value)
                    # Now redirect to site
                    return HttpResponseRedirect('/account/')

            else:
                data['computings'] = list(Computing.objects.filter(group=None)) + list(Computing.objects.filter(group__user=request.user))
        else:
            raise ErrorMessage('Unknown conf type \'{}\''.format(conf_type))


    return render(request, 'add_profile_conf.html', {'data': data})


#=========================
#  Task connect
#=========================

@private_view
def task_connect(request):

    task_uuid = request.GET.get('uuid', None)
    if not task_uuid:
        raise ErrorMessage('Empty task uuid')

    # Get the task
    task = Task.objects.get(uuid=task_uuid)

    if task.user != request.user:
        raise ErrorMessage('You do not have access to this task.')

    # Ensure that the tunnel and proxy are set up
    setup_tunnel_and_proxy(task)

    # Set default interface status as unknown
    task.interface_status = 'unknown'

    # Check if task interface is up
    if task.status == 'running':

        logger.debug('Checking if task interface is running by trying to establish connection via local tunnel on port "{}"'.format(task.tcp_tunnel_port))

        if task.container.interface_protocol.startswith('http'):
            try:
                if task.requires_tcp_tunnel:
                    # Check three times, as there might be some delay in establishing the tunnel
                    # in background in the above setup_tunnel_and_proxy() call
                    attempts = 0
                    while True:
                        try:
                            requests.get('{}://localhost:{}'.format(task.container.interface_protocol, task.tcp_tunnel_port), timeout=3)
                            logger.debug('Task interface is answering')
                            task.interface_status = 'running'
                        except:
                            if attempts > 2:
                                logger.debug('Too many attempts, giving up')
                                raise
                            else:
                                sleep_time = attempts + 1
                                logger.debug('Task interface not answering, retrying ({}s)...'.format(sleep_time))
                                attempts += 1
                                time.sleep(sleep_time)
                        else:
                            break
                else:
                    requests.get('{}://{}:{}'.format(task.container.interface_protocol, task.interface_ip, task.interface_port), timeout=3)
            except Exception as e:
                logger.debug('Could not connect to task interface ({})'.format(e))

        else:
            pass
            # # TODO: the following raises a TimeoutError even if the connection is active and with requests work. Why?
            # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            #     s.settimeout(3)
            #     try:
            #         s.connect(('localhost', task.tcp_tunnel_port))
            #         if not s.recv(10):
            #             logger.debug('No data read from socket')
            #             raise Exception('Could not read any data from socket')
            #     except Exception as e:
            #         logger.debug('Could not connect to task interface via socket ({})'.format(e))
            #         task.interface_status = 'unknown'
            #     else:
            #         logger.debug('Task interface is answering via socket')
            #         task.interface_status = 'running'

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

    # Ensure that the tunnel and proxy are set up
    setup_tunnel_and_proxy(task)

    # Get task and tunnel proxy host
    rosetta_tasks_proxy_host = get_rosetta_tasks_proxy_host()
    rosetta_tasks_tunnel_host = get_rosetta_tasks_tunnel_host()

    # Redirect to the task through the tunnel
    if task.requires_proxy:
        if task.requires_proxy_auth and task.auth_token and not task.container.disable_http_basicauth_embedding:
            user = request.user.email
            password = task.auth_token
            redirect_string = 'https://{}:{}@{}:{}/ad5aad4c-f68e-4077-b92f-8d9fd8f55428'.format(user, password, rosetta_tasks_proxy_host, task.tcp_tunnel_port)
        else:
            redirect_string = 'https://{}:{}'.format(rosetta_tasks_proxy_host, task.tcp_tunnel_port)
    else:
        redirect_string = '{}://{}:{}'.format(task.container.interface_protocol, rosetta_tasks_tunnel_host, task.tcp_tunnel_port)

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
    rosetta_tasks_proxy_host = get_rosetta_tasks_proxy_host()
    rosetta_tasks_tunnel_host = get_rosetta_tasks_tunnel_host()

    # Redirect to the task through the tunnel
    if task.requires_proxy:
        redirect_string = 'https://{}:{}'.format(rosetta_tasks_proxy_host, task.tcp_tunnel_port)
    else:
        redirect_string = '{}://{}:{}'.format(task.container.interface_protocol, rosetta_tasks_tunnel_host, task.tcp_tunnel_port)

    logger.debug('Task sharable link connect redirect: "{}"'.format(redirect_string))
    return redirect(redirect_string)


#=========================
#  New Binder Task
#=========================

@private_view
def new_binder_task(request, repository):

    # Init data
    data={}
    data['user']  = request.user

    # Convert the Git repository as a Docker container
    logger.debug('Got a new Binder task request for repository "%s"', repository)

    # Set repository name/tag/url
    repository_tag = repository.split('/')[-1]
    repository_url = repository.replace('/'+repository_tag, '')

    # I have no idea why the https:// of the repo part of the url gets transfrmed in https:/
    # Here i work around this, but TODO: understand what the hell is going on.
    if 'https:/' in repository_url and not 'https://' in repository_url:
        repository_url = repository_url.replace('https:/', 'https://')

    if not repository_tag:
        repository_tag='HEAD'

    data['repository_url'] = repository_url
    data['repository_tag'] = repository_tag

    data['mode'] = 'new_task' #new container

    # Render the import page. This will call an API, and when the import is done, it
    # will automatically redirect to the page "new_task/?step=two&task_container_uuid=..."
    return render(request, 'import_repository.html', {'data': data})


#=========================
#  Import repository
#=========================

@private_view
def import_repository(request):

    # Init data
    data={}
    data['user']  = request.user

    repository_url = request.GET.get('repository_url', None)
    # I have no idea why the https:// of the repo part of the url gets transfrmed in https:/
    # Here i work around this, but TODO: understand what the hell is going on.
    if 'https:/' in repository_url and not 'https://' in repository_url:
        repository_url = repository_url.replace('https:/', 'https://')

    repository_tag= request.GET.get('repository_tag', None)
    if not repository_tag:
        repository_tag='HEAD'

    data['repository_url'] = repository_url
    data['repository_tag'] = repository_tag

    data['container_name'] = request.GET.get('container_name', None)
    data['container_description'] = request.GET.get('container_description', None)

    data['mode'] = 'new_container'

    # Render the import page. This will call an API, and when the import is done, it
    # will automatically say "Ok, crrated, go to software".
    return render(request, 'import_repository.html', {'data': data})


