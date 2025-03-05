import os
from .models import TaskStatuses, KeyPair, Task, Storage
from .utils import os_shell, get_ssh_access_mode_credentials, sanitize_container_env_vars, booleanize, setup_tunnel_and_proxy
from .exceptions import ErrorMessage, ConsistencyException
from django.conf import settings

# Setup logging
import logging
logger = logging.getLogger(__name__)

ROSETTA_AGENT_CHECK_SSL = booleanize(os.environ.get('ROSETTA_AGENT_CHECK_SSL', True))
CHECK_CURL_CERT_STR = '--insecure' if not ROSETTA_AGENT_CHECK_SSL else ''

class ComputingManager(object):

    def __init__(self, computing):
        self.computing = computing

    def start_task(self, task, **kwargs):

        # Check for run task logic implementation
        try:
            self._start_task
        except AttributeError:
            raise NotImplementedError('Not implemented')

        # Call actual run task logic
        self._start_task(task, **kwargs)


    def stop_task(self, task, **kwargs):

        # Check for stop task logic implementation
        try:
            self._stop_task
        except AttributeError:
            raise NotImplementedError('Not implemented')

        # Call actual stop task logic
        self._stop_task(task, **kwargs)

        # Ok, save status as deleted
        task.status = 'stopped'
        task.save()

        # Check if the tunnel is active and if so kill it
        logger.debug('Checking if task "{}" has a running tunnel'.format(task.uuid))
        check_command = 'ps -ef | grep ":'+str(task.tcp_tunnel_port)+':'+str(task.interface_ip)+':'+str(task.interface_port)+'" | grep -v grep | awk \'{print $2}\''
        logger.debug(check_command)
        out = os_shell(check_command, capture=True)
        logger.debug(out)
        if out.exit_code == 0:
            logger.debug('Task "{}" has a running tunnel, killing it'.format(task.uuid))
            tunnel_pid = out.stdout
            # Kill Tunnel command
            kill_tunnel_command= 'kill -9 {}'.format(tunnel_pid)

            # Log
            logger.debug('Killing tunnel with command: {}'.format(kill_tunnel_command))

            # Execute
            os_shell(kill_tunnel_command, capture=True)
            if out.exit_code != 0:
                raise Exception(out.stderr)


    def get_task_log(self, task, **kwargs):

        # Check for get task log logic implementation
        try:
            self._get_task_log
        except AttributeError:
            raise NotImplementedError('Not implemented')

        # Call actual get task log logic
        return self._get_task_log(task, **kwargs)

    def is_configured_for(self, user):
        return True


class StandaloneComputingManager(ComputingManager):
    pass


class ClusterComputingManager(ComputingManager):
    pass


class SSHComputingManager(ComputingManager):

    def is_configured_for(self, user):
        try:
            get_ssh_access_mode_credentials(self.computing, user)
        except:
            return False
        else:
            return True



class InternalStandaloneComputingManager(StandaloneComputingManager):

    def _start_task(self, task):

        # Init run command #--cap-add=NET_ADMIN --cap-add=NET_RAW
        run_command  = 'sudo docker run  --network=rosetta_default --name {}'.format(task.uuid)

        if task.container.interface_port == 22:
            if not task.container.supports_custom_interface_port:
                raise ErrorMessage('This task container use the port number 22 which often has issues on the internal computing resource, and does not support custom interface ports, so we cannot run it.')
            else:
                task_port = 2222
                run_command += ' -eBASE_PORT={} '.format(task_port)
        else:
            task_port = task.container.interface_port

        # Pass if any
        if not task.requires_proxy and task.password:
            run_command += ' -eAUTH_PASS={} '.format(task.password)

        # Env vars if any
        if task.container.env_vars:

            # Sanitize again just in case the DB got somehow compromised:
            env_vars = sanitize_container_env_vars(task.container.env_vars)

            for env_var in env_vars:
                run_command += ' -e{}={} '.format(env_var, env_vars[env_var])

        # User data volume
        #run_command += ' -v {}/user-{}:/data'.format(settings.LOCAL_USER_DATA_DIR, task.user.id)

        # Handle storages (binds)
        binds = ''
        storages = Storage.objects.filter(computing=self.computing)
        for storage in storages:
            if storage.type == 'generic_posix' and storage.bind_path:

                # Expand the base path
                expanded_base_path = storage.base_path
                if '$USER' in expanded_base_path:
                    expanded_base_path = expanded_base_path.replace('$USER', task.user.username)

                # Expand the bind_path
                expanded_bind_path = storage.bind_path
                if '$USER' in expanded_bind_path:
                    expanded_bind_path = expanded_bind_path.replace('$USER', task.user.username)

                # Read only?
                if storage.read_only:
                    mode_string = ':ro'
                else:
                    mode_string = ''

                # Add the bind
                if not binds:
                    binds = '-v{}:{}{}'.format(expanded_base_path, expanded_bind_path, mode_string)
                else:
                    binds += ' -v{}:{}{}'.format(expanded_base_path, expanded_bind_path, mode_string)

        # Host name, image entry command
        run_command += ' {} -h task-{} --name task-{} -d -t {}/{}:{}'.format(binds, task.short_uuid, task.short_uuid, task.container.registry, task.container.image_name, task.container.image_tag)

        # Debug
        logger.debug('Running new task with command="{}"'.format(run_command))

        # Run the task
        out = os_shell(run_command, capture=True)
        if out.exit_code != 0:
            logger.error('Got error in starting task: {}'.format(out))
            raise Exception(out.stderr)
        else:

            # Get task IP address
            out = os_shell('export CONTAINER_ID=$(sudo docker ps -a --filter name=task-'+task.short_uuid+' --format {{.ID}}) && sudo docker inspect --format \'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\' $CONTAINER_ID | tail -n1', capture=True)
            if out.exit_code != 0:
                raise Exception('Error: ' + out.stderr)
            task_ip = out.stdout

            # Set fields
            task.status = TaskStatuses.running
            task.interface_ip = task_ip
            task.interface_port = task_port

            # Save
            task.save()

        # Setup the tunnel if using a custom protocol (otherwise it will get set up via the "connect" button)
        if task.container.interface_protocol not in ['http', 'https']:
            setup_tunnel_and_proxy(task)

    def _stop_task(self, task):

        # Delete the Docker container
        stop_command = 'export CONTAINER_ID=$(sudo docker ps -a --filter name=task-'+task.short_uuid+' --format {{.ID}}) && sudo docker stop $CONTAINER_ID && sudo docker rm $CONTAINER_ID'

        out = os_shell(stop_command, capture=True)
        if out.exit_code != 0:
            if 'No such container' in out.stderr:
                # No container was found
                pass
            elif 'requires at least 1 argument' in out.stderr:
                # No container was found
                pass
            else:
                raise Exception(out.stderr)

        # Set task as stopped
        task.status = TaskStatuses.stopped
        task.save()


    def _get_task_log(self, task, **kwargs):

        # View the Docker container log (attach)
        view_log_command = 'export CONTAINER_ID=$(sudo docker ps -a --filter name=task-'+task.short_uuid+' --format {{.ID}}) && sudo docker logs $CONTAINER_ID'
        logger.debug(view_log_command)
        out = os_shell(view_log_command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        else:
            return out.stdout



class SSHStandaloneComputingManager(StandaloneComputingManager, SSHComputingManager):

    def _start_task(self, task, **kwargs):
        logger.debug('Starting a remote task "{}"'.format(self.computing))

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # Get webapp conn string
        from.utils import get_webapp_conn_string
        webapp_conn_string = get_webapp_conn_string()

        # Handle container engine
        container_engine = None
        if task.computing_options:
            container_engine = task.computing_options.get('container_engine', None)
        if not container_engine:
            container_engine = task.computing.default_container_engine

        # engine-specific part
        if container_engine == 'singularity':

            #if not task.container.supports_custom_interface_port:
            #     raise Exception('This task does not support dynamic port allocation and is therefore not supported using singularity on Slurm')

            # Set pass if any
            authstring = ''
            if not task.requires_proxy_auth and task.password:
                authstring = ' && export SINGULARITYENV_AUTH_PASS={} '.format(task.password)

            # Env vars if any
            if task.container.env_vars:
                varsstring = ''
                # Sanitize again just in case the DB got somehow compromised:
                env_vars = sanitize_container_env_vars(task.container.env_vars)

                for env_var in env_vars:
                    varsstring += ' && export SINGULARITYENV_{}={} '.format(env_var, env_vars[env_var])
            else:
                varsstring = ''

            # Handle storages (binds)
            binds = ''
            storages = Storage.objects.filter(computing=self.computing)
            for storage in storages:
                if storage.type == 'generic_posix' and storage.bind_path:

                    # Expand the base path
                    expanded_base_path = storage.base_path
                    if '$SSH_USER' in expanded_base_path:
                        if storage.access_through_computing:
                            expanded_base_path = expanded_base_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_base_path:
                        expanded_base_path = expanded_base_path.replace('$USER', task.user.username)

                    # Expand the bind_path
                    expanded_bind_path = storage.bind_path
                    if '$SSH_USER' in expanded_bind_path:
                        if storage.access_through_computing:
                            expanded_bind_path = expanded_bind_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_bind_path:
                        expanded_bind_path = expanded_bind_path.replace('$USER', task.user.username)

                    # Add the bind
                    if not binds:
                        binds = '-B {}:{}'.format(expanded_base_path, expanded_bind_path)
                    else:
                        binds += ',{}:{}'.format(expanded_base_path, expanded_bind_path)

            run_command  = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} '.format(computing_port, computing_keys.private_key_file, computing_user, computing_host)
            run_command += '/bin/bash -c \'"rm -rf /tmp/{}_data && mkdir -p /tmp/{}_data/tmp && mkdir -p /tmp/{}_data/home && chmod 700 /tmp/{}_data && '.format(task.uuid, task.uuid, task.uuid, task.uuid)
            run_command += 'curl {} {}/api/v1/base/agent/?task_uuid={} -o /tmp/{}_data/agent.py &> /dev/null && export BASE_PORT=\$(python3 /tmp/{}_data/agent.py 2> /tmp/{}_data/task.log) && '.format(CHECK_CURL_CERT_STR, webapp_conn_string, task.uuid, task.uuid, task.uuid, task.uuid)
            run_command += 'export SINGULARITY_NOHTTPS=true && export SINGULARITYENV_BASE_PORT=\$BASE_PORT {} {} &&'.format(authstring, varsstring)
            run_command += 'exec nohup singularity run {} --pid --writable-tmpfs --no-home --home=/home/metauser --workdir /tmp/{}_data/tmp -B/tmp/{}_data/home:/home --containall --cleanenv '.format(binds, task.uuid, task.uuid)

            # Container part
            run_command+='docker://{}/{}:{} &>> /tmp/{}_data/task.log & echo \$!"\''.format(task.container.registry, task.container.image_name, task.container.image_tag, task.uuid)


        elif container_engine in ['docker', 'podman']:

            # Set pass if any
            authstring = ''
            if not task.requires_proxy_auth and task.password:
                authstring = ' -e AUTH_PASS={} '.format(task.password)

            # Env vars if any
            if task.container.env_vars:
                varsstring = ''
                # Sanitize again just in case the DB got somehow compromised:
                env_vars = sanitize_container_env_vars(task.container.env_vars)

                for env_var in env_vars:
                    varsstring += ' -e {}={} '.format(env_var, env_vars[env_var])
            else:
                varsstring = ''

            # Handle storages (binds)
            binds = ''
            storages = Storage.objects.filter(computing=self.computing)
            initialize_bind_paths_command = ''
            for storage in storages:
                if storage.type == 'generic_posix' and storage.bind_path:

                    # Expand the base path
                    expanded_base_path = storage.base_path
                    if '$SSH_USER' in expanded_base_path:
                        if storage.access_through_computing:
                            expanded_base_path = expanded_base_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_base_path:
                        expanded_base_path = expanded_base_path.replace('$USER', task.user.username)

                    initialize_bind_paths_command += 'mkdir -p {} && '.format(expanded_base_path)

                    # Expand the bind_path
                    expanded_bind_path = storage.bind_path
                    if '$SSH_USER' in expanded_bind_path:
                        if storage.access_through_computing:
                            expanded_bind_path = expanded_bind_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_bind_path:
                        expanded_bind_path = expanded_bind_path.replace('$USER', task.user.username)

                    # Read only?
                    if storage.read_only:
                        mode_string = ':ro'
                    else:
                        mode_string = ''

                    # Add the bind
                    if not binds:
                        binds = '-v{}:{}{}'.format(expanded_base_path, expanded_bind_path, mode_string)
                    else:
                        binds += ' -v{}:{}{}'.format(expanded_base_path, expanded_bind_path, mode_string)

            # TODO: remove this hardcoding
            prefix = 'sudo' if (computing_host == 'slurmclusterworker' and container_engine=='docker') else ''

            run_command  = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} '.format(computing_port, computing_keys.private_key_file, computing_user, computing_host)
            run_command += '/bin/bash -c \'"{}rm -rf /tmp/{}_data && mkdir /tmp/{}_data && chmod 700 /tmp/{}_data && '.format(initialize_bind_paths_command, task.uuid, task.uuid, task.uuid)
            run_command += 'curl {} {}/api/v1/base/agent/?task_uuid={} -o /tmp/{}_data/agent.py &> /dev/null && export TASK_PORT=\$(python3 /tmp/{}_data/agent.py 2> /tmp/{}_data/task.log) && '.format(CHECK_CURL_CERT_STR, webapp_conn_string, task.uuid, task.uuid, task.uuid, task.uuid)
            run_command += 'exec nohup {} {} run -p \$TASK_PORT:{} {} {} {} '.format(prefix, container_engine, task.container.interface_port, authstring, varsstring, binds)
            if container_engine == 'podman':
                run_command += '--network=private --uts=private --userns=keep-id '
            #run_command += '-d -t {}/{}:{}'.format(task.container.registry, task.container.image_name, task.container.image_tag)
            run_command += '-h task-{} --name task-{}  -t {}/{}:{}'.format(task.short_uuid, task.short_uuid, task.container.registry, task.container.image_name, task.container.image_tag)
            run_command += '&>> /tmp/{}_data/task.log &"\''.format(task.uuid)

        else:
            raise NotImplementedError('Container engine {} not supported'.format(container_engine))

        out = os_shell(run_command, capture=True)
        if out.exit_code != 0:
            logger.error('Got error in starting task: {}'.format(out))
            raise Exception(out.stderr)

        # Log
        logger.debug('Shell exec output: "{}"'.format(out))

        # Load back the task to avoid  concurrency problems in the agent call
        task_uuid = task.uuid
        task = Task.objects.get(uuid=task_uuid)

        # Save the task (container) id for Singularity, which is the PID echoed by the command above
        if container_engine == 'singularity':
            task.process_id = out.stdout

        # Save
        task.save()

        # Setup the tunnel if using a custom protocol (otherwise it will get set up via the "connect" button)
        if task.container.interface_protocol not in ['http', 'https']:
            setup_tunnel_and_proxy(task)


    def _stop_task(self, task, **kwargs):

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # Handle container engine
        container_engine = None
        if task.computing_options:
            container_engine = task.computing_options.get('container_engine', None)
        if not container_engine:
            container_engine = task.computing.default_container_engine

        if container_engine=='singularity':
            internal_stop_command = 'kill -9 {}'.format(task.process_id)
        elif container_engine in ['docker', 'podman']:
            # TODO: remove this hardcoding
            prefix = 'sudo' if (computing_host == 'slurmclusterworker' and container_engine=='docker') else ''
            internal_stop_command = 'export CONTAINER_ID=$('+prefix+' '+container_engine+' ps -a --filter name=task-'+task.short_uuid+' --format {{.ID}}) &&'
            internal_stop_command += 'if [ "x\$CONTAINER_ID" != "x" ]; then {} {} stop \$CONTAINER_ID && {} {} rm \$CONTAINER_ID; fi'.format(prefix,container_engine,prefix,container_engine)
        else:
            raise NotImplementedError('Container engine {} not supported'.format(container_engine))

        stop_command = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} \'/bin/bash -c "{}"\''.format(computing_port, computing_keys.private_key_file, computing_user, computing_host, internal_stop_command)
        out = os_shell(stop_command, capture=True)

        if out.exit_code != 0:
            if ('No such process' in out.stderr) or ('No such container' in out.stderr) or ('no container' in out.stderr) or ('missing' in out.stderr):
                pass
            else:
                logger.critical('Got error in stopping task: {}'.format(out))
                raise Exception(out.stderr)

        # Set task as stopped
        task.status = TaskStatuses.stopped
        task.save()


    def _get_task_log(self, task, **kwargs):

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # Handle container engine
        container_engine = None
        if task.computing_options:
            container_engine = task.computing_options.get('container_engine', None)
        if not container_engine:
            container_engine = task.computing.default_container_engine

        if container_engine=='singularity':
            internal_view_log_command = 'cat /tmp/{}_data/task.log'.format(task.uuid)
        elif container_engine in ['docker','podman']:
            # TODO: consider podman/docker logs?
            internal_view_log_command = 'cat /tmp/{}_data/task.log'.format(task.uuid)
        else:
            raise NotImplementedError('Container engine {} not supported'.format(container_engine))

        # Prepare full comand
        view_log_command = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} \'/bin/bash -c "{}"\''.format(computing_port, computing_keys.private_key_file, computing_user, computing_host, internal_view_log_command)

        # Execute
        out = os_shell(view_log_command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        else:
            return out.stdout


class SlurmSSHClusterComputingManager(ClusterComputingManager, SSHComputingManager):

    def _start_task(self, task, **kwargs):
        logger.debug('Starting a remote task "{}"'.format(self.computing))

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # Get webapp conn string
        from.utils import get_webapp_conn_string
        webapp_conn_string = get_webapp_conn_string()

        # Initialize sbatch args (force 1 task for now)
        sbatch_args = '-N1 '

        # Get task computing parameters and set sbatch args
        if task.computing_options:
            task_partition = task.computing_options.get('partition', None)
            task_cpus = task.computing_options.get('cpus', None)
            task_memory = task.computing_options.get('memory', None)

            # Set sbatch args
            if task_partition:
                sbatch_args += '-p {} '.format(task_partition)
            if task_cpus:
                sbatch_args += '-c {} '.format(task_cpus)
            if task_memory:
                sbatch_args += '--mem {} '.format(task_memory)

        # Set output and error files
        sbatch_args += ' --output=\$HOME/{}.log --error=\$HOME/{}.log '.format(task.uuid, task.uuid)

        # Handle container engine
        container_engine = None
        if task.computing_options:
            container_engine = task.computing_options.get('container_engine', None)
        if not container_engine:
            container_engine = task.computing.default_container_engine

        # engine-specific part
        if container_engine == 'singularity':

            #if not task.container.supports_custom_interface_port:
            #     raise Exception('This task does not support dynamic port allocation and is therefore not supported using singularity on Slurm')

            # Set pass if any
            authstring = ''
            if not task.requires_proxy_auth and task.password:
                authstring = ' && export SINGULARITYENV_AUTH_PASS={} '.format(task.password)

            # Env vars if any
            if task.container.env_vars:
                varsstring = ''
                # Sanitize again just in case the DB got somehow compromised:
                env_vars = sanitize_container_env_vars(task.container.env_vars)

                for env_var in env_vars:
                    varsstring += ' && export SINGULARITYENV_{}={} '.format(env_var, env_vars[env_var])
            else:
                varsstring = ''

            # Handle storages (binds)
            binds = ''
            storages = Storage.objects.filter(computing=self.computing)
            for storage in storages:
                if storage.type == 'generic_posix' and storage.bind_path:

                    # Expand the base path
                    expanded_base_path = storage.base_path
                    if '$SSH_USER' in expanded_base_path:
                        if storage.access_through_computing:
                            expanded_base_path = expanded_base_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_base_path:
                        expanded_base_path = expanded_base_path.replace('$USER', task.user.username)

                    # Expand the bind_path
                    expanded_bind_path = storage.bind_path
                    if '$SSH_USER' in expanded_bind_path:
                        if storage.access_through_computing:
                            expanded_bind_path = expanded_bind_path.replace('$SSH_USER', computing_user)
                        else:
                            raise NotImplementedError('Accessing a storage with ssh+cli without going through its computing resource is not implemented')
                    if '$USER' in expanded_bind_path:
                        expanded_bind_path = expanded_bind_path.replace('$USER', task.user.username)

                    # Add the bind
                    if not binds:
                        binds = '-B {}:{}'.format(expanded_base_path, expanded_bind_path)
                    else:
                        binds += ',{}:{}'.format(expanded_base_path, expanded_bind_path)

            run_command = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} '.format(computing_port, computing_keys.private_key_file, computing_user, computing_host)
            run_command += '\'bash -c "echo \\"#!/bin/bash\ncurl {} {}/api/v1/base/agent/?task_uuid={} -o \$HOME/agent_{}.py &> \$HOME/{}.log && export BASE_PORT=\\\\\\$(python3 \$HOME/agent_{}.py 2> \$HOME/{}.log) && '.format(CHECK_CURL_CERT_STR, webapp_conn_string, task.uuid, task.uuid, task.uuid, task.uuid, task.uuid)
            run_command += 'export SINGULARITY_NOHTTPS=true && export SINGULARITYENV_BASE_PORT=\\\\\\$BASE_PORT {} {} && '.format(authstring, varsstring)
            run_command += 'rm -rf /tmp/{}_data && mkdir -p /tmp/{}_data/tmp &>> \$HOME/{}.log && mkdir -p /tmp/{}_data/home &>> \$HOME/{}.log && chmod 700 /tmp/{}_data && '.format(task.uuid, task.uuid, task.uuid, task.uuid, task.uuid, task.uuid)
            run_command += 'exec nohup singularity run {} --pid --writable-tmpfs --no-home --home=/home/metauser --workdir /tmp/{}_data/tmp -B/tmp/{}_data/home:/home --containall --cleanenv '.format(binds, task.uuid, task.uuid)

            # Double to escape for Python, six for shell (double times three as \\\ escapes a single slash in shell)
            run_command+='docker://{}/{}:{} &> \$HOME/{}.log\\" > \$HOME/{}.sh && sbatch {} \$HOME/{}.sh"\''.format(task.container.registry, task.container.image_name, task.container.image_tag, task.uuid, task.uuid, sbatch_args, task.uuid)

        else:
            raise NotImplementedError('Container engine {} not supported'.format(container_engine))

        out = os_shell(run_command, capture=True)
        if out.exit_code != 0:
            logger.error('Got error in starting task: {}'.format(out))
            raise Exception(out.stderr)

        # Log
        logger.debug('Shell exec output: "{}"'.format(out))

        # Parse sbatch output. Example: Output(stdout='Submitted batch job 3', stderr='', exit_code=0)
        job_id = out.stdout.split(' ')[-1]
        try:
            int(job_id)
        except:
            raise Exception('Cannot find int job id from output string "{}"'.format(out.stdout))

        # Load back the task to avoid concurrency problems in the agent call
        task_uuid = task.uuid
        task = Task.objects.get(uuid=task_uuid)

        # Save job id
        task.job_id = job_id

        # Set status (only fi we get here before the agent which sets the status as running via the API)
        if task.status != TaskStatuses.running:
            task.status = TaskStatuses.sumbitted

        # Save
        task.save()

        # Setup the tunnel if using a custom protocol (otherwise it will get set up via the "connect" button)
        if task.container.interface_protocol not in ['http', 'https']:
            setup_tunnel_and_proxy(task)

    def _stop_task(self, task, **kwargs):

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # Stop the task remotely
        stop_command = 'ssh -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} \'/bin/bash -c "scancel {}"\''.format(computing_keys.private_key_file, computing_user, computing_host, task.job_id)
        out = os_shell(stop_command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)

        # Set task as topped
        task.status = TaskStatuses.stopped
        task.save()


    def _get_task_log(self, task, **kwargs):

        # Get credentials
        computing_user, computing_host, computing_port, computing_keys = get_ssh_access_mode_credentials(self.computing, task.user)

        # View log remotely
        view_log_command = 'ssh -p {} -o LogLevel=ERROR -i {} -4 -o StrictHostKeyChecking=no {}@{} \'/bin/bash -c "cat \$HOME/{}.log"\''.format(computing_port, computing_keys.private_key_file, computing_user, computing_host, task.uuid)

        out = os_shell(view_log_command, capture=True)
        if out.exit_code != 0:
            raise Exception(out.stderr)
        else:
            return out.stdout

