from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from ...models import Profile, Container, Computing, Storage, KeyPair, Text

class Command(BaseCommand):
    help = 'Adds the admin superuser with \'a\' password.'

    def handle(self, *args, **options):

        #=====================
        #  Admin
        #=====================
        try:
            User.objects.get(username='admin')
            print('Not creating admin user as it already exist')
            
        except User.DoesNotExist:
            print('Creating admin user with default password')
            admin = User.objects.create_superuser('admin', 'admin@example.com', 'admin')
            Profile.objects.create(user=admin)
        
        #=====================    
        #  Testuser
        #=====================
        try:
            testuser = User.objects.get(username='testuser')
            print('Not creating test user as it already exists')
        
        except User.DoesNotExist:
            print('Creating test user with default password')
            testuser = User.objects.create_user('testuser', 'testuser@rosetta.platform', 'testpass')
            print('Making testuser admin')
            testuser.is_staff = True
            testuser.is_admin=True
            testuser.is_superuser=True
            testuser.save() 
            print('Creating testuser profile')
            Profile.objects.create(user=testuser, authtoken='129aac94-284a-4476-953c-ffa4349b4a50')

            # Create default keys
            print('Creating testuser default keys')
            KeyPair.objects.create(user = testuser,
                                   default = True,
                                   private_key_file = '/rosetta/.ssh/id_rsa',
                                   public_key_file = '/rosetta/.ssh/id_rsa.pub')
        

        #=====================    
        #  Platform keys
        #=====================
        # TODO: create a different pair
        try:
            KeyPair.objects.get(user=None, default=True)
            print('Not creating default platform keys as they already exist')
        
        except KeyPair.DoesNotExist:
            print('Creating platform default keys')
            KeyPair.objects.create(user = None,
                                   default = True,
                                   private_key_file = '/rosetta/.ssh/id_rsa',
                                   public_key_file = '/rosetta/.ssh/id_rsa.pub')
                  

        #=====================
        #  Default home text
        #=====================
        default_home_text_content = '''
<div class="span8 offset2" style="margin: 30px auto; max-width:800px">
  Welcome to Rosetta!
  <br/><br/>
  This is the default home text loaded after populating the platform with the default/demo data.
  To change it, head to the <a href="/admin">admin</a> page and edit the <code>Text</code> model.
  <br/><br/>
  The default installation provides a test user register with email <code>testuser@rosetta.platform</code>
  and password <code>testpass</code>, which you can use to login on the menu on the rightand give Rosetta
  a try immediately. If you run with the default docker-compose file (i.e. you just run 
  <code>rosetta/setup</code>), then you will also have a few demo computing resources you can play with
  out-of-the-box, including a small Slurm cluster. Otherwise, you will need to setup your own computing
  resources either platform-wide or as user.
</div>
'''
        home_text = Text.objects.filter(id='home')
        if home_text:
            print('Not creating default home text as already present')
        else:
            print('Creating default home text...')
            Text.objects.create(id='home', content=default_home_text_content)


        #===================== 
        # Platform containers
        #===================== 
        
        platform_containers = Container.objects.filter(user=None)
        if platform_containers:
            print('Not creating public containers as they already exist')
        else:
            print('Creating platform containers...')
            
            # Minimal Desktop
            Container.objects.create(user     = None,
                                     name     = 'Minimal Desktop ',
                                     description = 'A minimal desktop environment providing basic window management functionalities and a terminal.',
                                     registry = 'docker.io',
                                     image    = 'sarusso/minimaldesktop',
                                     tag      = 'v0.2.0',
                                     arch = 'x86_64',
                                     os = 'linux',
                                     interface_port     = '8590',
                                     interface_protocol = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True)

            # Basic Desktop
            Container.objects.create(user     = None,
                                     name     = 'Basic Desktop',
                                     description = 'A basic desktop environment. Provides a terminal, a file manager, a web browser and other generic applications.',
                                     registry = 'docker.io',
                                     image    = 'sarusso/basicdesktop',
                                     tag      = 'v0.2.0',
                                     arch = 'x86_64',
                                     os = 'linux',
                                     interface_port     = '8590',
                                     interface_protocol = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True)
 
 
            # Jupyter Notebook 
            Container.objects.create(user     = None,
                                     name     = 'Jupyter Notebook',
                                     description = 'A Jupyter Notebook server',
                                     registry = 'docker.io',
                                     image    = 'sarusso/jupyternotebook',
                                     tag      = 'v0.2.0',
                                     arch = 'x86_64',
                                     os = 'linux',
                                     interface_port     = '8888',
                                     interface_protocol = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True)

            # SSH server
            Container.objects.create(user     = None,
                                     name     = 'SSH server',
                                     description = 'A SSH server supporting X forwarding as well.',
                                     registry = 'docker.io',
                                     image    = 'sarusso/ssh',
                                     tag      = 'v0.2.0',
                                     arch = 'x86_64',
                                     os = 'linux',
                                     interface_port     = '22',
                                     interface_protocol = 'ssh',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True)

        #===================== 
        # Testuser containers
        #===================== 
        #testuser_containers = Container.objects.filter(user=testuser)
        #if testuser_containers:
        #    print('Not creating testuser private containers as they already exist')
        #else:
        #    print('Creating testuser private containers...')
        #
        #    # Jupyter Singularity
        #    Container.objects.create(user     = testuser,
        #                             name     = 'Jupyter Notebook',
        #                             description = 'The official Jupyter Notebook container.',
        #                             registry = 'docker.io',
        #                             image    = 'jupyter/base-notebook',
        #                             tag      = 'latest',
        #                             arch = 'x86_64',
        #                             os = 'linux',
        #                             interface_port     = '8888',
        #                             interface_protocol = 'http',
        #                             interface_transport = 'tcp/ip',
        #                             supports_custom_interface_port = False,
        #                             supports_interface_auth = False)


        #===================== 
        # Computing resources
        #===================== 
        computing_resources = Computing.objects.all()
        if computing_resources:
            print('Not creating demo computing resources as they already exist')
        else:
            print('Creating demo computing resources...')

            # Demo internal computing
            Computing.objects.create(name = 'Demo Internal',
                                     description = 'A demo internal computing resource.',
                                     type = 'standalone',
                                     access_mode = 'internal',
                                     auth_mode = 'internal',
                                     wms = None,
                                     container_runtimes = 'docker')

            
            # Demo standalone computing plus conf
            demo_singlenode_computing = Computing.objects.create(name = 'Demo Standalone',
                                                                 description = 'A demo standalone computing resource.',
                                                                 type = 'standalone',
                                                                 access_mode = 'ssh+cli',
                                                                 auth_mode = 'user_keys',
                                                                 wms = None,
                                                                 conf = {'host': 'slurmclusterworker-one'},
                                                                 container_runtimes = 'singularity')
    
            # Add testuser extra conf for this computing resource
            testuser.profile.add_extra_conf(conf_type = 'computing_user', object=demo_singlenode_computing, value= 'slurmtestuser')

            #  Demo cluster computing plus conf
            demo_slurm_computing = Computing.objects.create(name = 'Demo Cluster',
                                                            description = 'A demo cluster computing resource.',
                                                            type = 'cluster',
                                                            access_mode = 'ssh+cli',
                                                            auth_mode = 'user_keys',
                                                            wms = 'slurm',
                                                            conf = {'host': 'slurmclustermaster-main', 'default_partition': 'partition1'},
                                                            container_runtimes = 'singularity')
           
            # Add testuser extra conf for this computing resource
            testuser.profile.add_extra_conf(conf_type = 'computing_user', object=demo_slurm_computing, value= 'slurmtestuser')

        #===================== 
        # Storages
        #===================== 
        storages = Storage.objects.all()
        if storages:
            print('Not creating demo storage resources as they already exist')
        else:
            print('Creating demo storage resources...')
 
            # Get demo computing resources
            demo_computing_resources = []
            try:    
                demo_slurm_computing = Computing.objects.get(name='Demo Cluster')
                demo_computing_resources.append(demo_slurm_computing)
            except:
                pass
            try:
                demo_standalone_computing = Computing.objects.get(name='Demo Standalone')
                demo_computing_resources.append(demo_standalone_computing)
            except:
                pass
             
 
            for computing in demo_computing_resources:
                # Demo shared computing plus conf
                Storage.objects.create(computing = computing,
                                       access_through_computing = True,
                                       name = 'Shared',
                                       type = 'generic_posix',
                                       access_mode = 'ssh+cli',
                                       auth_mode = 'user_keys',
                                       base_path = '/shared/data/shared',
                                       bind_path = '/storages/shared')
     
                # Demo shared computing plus conf
                Storage.objects.create(computing = computing,
                                       access_through_computing = True,
                                       name = 'Personal',
                                       type = 'generic_posix',
                                       access_mode = 'ssh+cli',
                                       auth_mode = 'user_keys',
                                       base_path = '/shared/data/users/$SSH_USER',
                                       bind_path = '/storages/personal')
 





