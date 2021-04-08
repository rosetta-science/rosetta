from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from ...models import Profile, Container, Computing, ComputingSysConf, ComputingUserConf, KeyPair, Text

class Command(BaseCommand):
    help = 'Adds the admin superuser with \'a\' password.'

    def handle(self, *args, **options):

        # Admin
        try:
            User.objects.get(username='admin')
            print('Not creating admin user as it already exist')
        except User.DoesNotExist:
            print('Creating admin user with default password')
            admin = User.objects.create_superuser('admin', 'admin@example.com', 'admin')
            Profile.objects.create(user=admin)
        
        # Testuser
        try:
            testuser = User.objects.get(username='testuser')
            print('Not creating test user as it already exist')
        
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
            print('Creating testuser defualt keys')
            KeyPair.objects.create(user = testuser,
                                default = True,
                                private_key_file = '/rosetta/.ssh/id_rsa',
                                public_key_file = '/rosetta/.ssh/id_rsa.pub')

        # Default homepage text
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


        # Public containers
        public_containers = Container.objects.filter(user=None)
        if public_containers:
            print('Not creating public containers as they already exist')
        else:
            print('Creating public containers...')
            
            # MinimalMetaDesktop Docker (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'MinimalMetaDesktop latest',
                                     image    = 'sarusso/minimalmetadesktop',
                                     type     = 'docker',
                                     registry = 'docker_hub',
                                     ports    = '8590',
                                     protocol = 'https',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)

            # BasicMetaDesktop Docker (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'BasicMetaDesktop latest',
                                     image    = 'sarusso/basicmetadesktop',
                                     type     = 'docker',
                                     registry = 'docker_hub',
                                     protocol = 'https',
                                     ports    = '8590',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)


            # DevMetaDesktop Docker (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'DevMetaDesktop latest',
                                     image    = 'sarusso/devmetadesktop',
                                     type     = 'docker',
                                     registry = 'docker_hub',
                                     protocol = 'https',
                                     ports    = '8590',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)


            # MinimalMetaDesktop Singularity (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'MinimalMetaDesktop latest',
                                     image    = 'sarusso/minimalmetadesktop',
                                     type     = 'singularity',
                                     registry = 'docker_hub',
                                     protocol = 'https',
                                     ports    = '8590',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)
            

            # BasicMetaDesktop Singularity (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'BasicMetaDesktop latest',
                                     image    = 'sarusso/basicmetadesktop',
                                     type     = 'singularity',
                                     registry = 'docker_hub',
                                     protocol = 'https',
                                     ports    = '8590',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)


            # DevMetaDesktop Singularity (sarusso repo)
            Container.objects.create(user     = None,
                                     name     = 'DevMetaDesktop latest',
                                     image    = 'sarusso/devmetadesktop',
                                     type     = 'singularity',
                                     registry = 'docker_hub',
                                     protocol = 'https',
                                     ports    = '8590',
                                     supports_dynamic_ports = True,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = True)


            # MetaDesktop Singularity (local)
            #Container.objects.create(user     = None,
            #                         name     = 'MetaDesktop latest',
            #                         image    = 'rosetta/metadesktop',
            #                         type     = 'singularity',
            #                         registry = 'docker_local',
            #                         ports    = '8590',
            #                         supports_dynamic_ports = True,
            #                         supports_user_auth     = False,
            #                         supports_pass_auth     = True)



            # Astrocook
            #Container.objects.create(user     = None,
            #                         name     = 'Astrocook b2b819e',
            #                         image    = 'sarusso/astrocook:b2b819e',
            #                         type     = 'docker',
            #                         registry = 'docker_local',
            #                         ports    = '8590',
            #                         supports_dynamic_ports = False,
            #                         supports_user_auth     = False,
            #                         supports_pass_auth     = False)


        # Private containers
        testuser_containers = Container.objects.filter(user=testuser)
        if testuser_containers:
            print('Not creating testuser private containers as they already exist')
        else:
            print('Creating testuser private containers...')

            # Jupyter Singularity
            Container.objects.create(user     = testuser,
                                     name     = 'Jupyter Notebook latest',
                                     image    = 'jupyter/base-notebook',
                                     type     = 'singularity',
                                     registry = 'docker_hub',
                                     ports    = '8888', 
                                     supports_dynamic_ports = False,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = False)
            
            # Jupyter Docker
            Container.objects.create(user     = testuser,
                                     name     = 'Jupyter Notebook latest',
                                     image    = 'jupyter/base-notebook',
                                     type     = 'docker',
                                     registry = 'docker_hub',
                                     ports    = '8888', 
                                     supports_dynamic_ports = False,
                                     supports_user_auth     = False,
                                     supports_pass_auth     = False)

        # Computing resources
        computing_resources = Computing.objects.all()
        if computing_resources:
            print('Not creating demo computing resources as they already exist')
        else:
            print('Creating demo computing resources containers...')

            #==============================
            #  Demo Internal computing
            #==============================
            Computing.objects.create(user = None,
                                     name = 'Demo Internal',
                                     type = 'singlenode',
                                     access_method = 'internal',
                                     requires_sys_conf  = False,
                                     requires_user_conf = False,
                                     requires_user_keys = False,
                                     supports_docker = True,
                                     supports_singularity = False)


            #==============================
            # Demo Single Node computing 
            #==============================    
            demo_singlenode_computing = Computing.objects.create(user = None,
                                                                 name = 'Demo Single Node',
                                                                 type = 'singlenode',
                                                                 access_method = 'ssh',
                                                                 requires_sys_conf  = True,
                                                                 requires_user_conf = True,
                                                                 requires_user_keys = True,
                                                                 supports_docker = True,
                                                                 supports_singularity = True)
    
            ComputingSysConf.objects.create(computing = demo_singlenode_computing,
                                            data      = {'host': 'slurmclusterworker-one',
                                                         'binds': '/shared/data/users:/shared/data/users,/shared/scratch:/shared/scratch'})

            ComputingUserConf.objects.create(user      = testuser,
                                             computing = demo_singlenode_computing,
                                             data      = {'user': 'slurmtestuser'})
         

            #==============================
            #  Demo Cluster computing
            #==============================
            demo_slurm_computing = Computing.objects.create(user = None,
                                                            name = 'Demo Cluster',
                                                            type = 'cluster',
                                                            access_method = 'slurm+ssh',
                                                            requires_sys_conf  = True,
                                                            requires_user_conf = True,
                                                            requires_user_keys = True,
                                                            supports_docker = False,
                                                            supports_singularity = True)
    
            # Create demo slurm sys computing conf
            ComputingSysConf.objects.create(computing = demo_slurm_computing,
                                            data      = {'host': 'slurmclustermaster-main', 'default_partition': 'partition1',
                                                         'binds': '/shared/data/users:/shared/data/users,/shared/scratch:/shared/scratch'})

            # Create demo slurm user computing conf
            ComputingUserConf.objects.create(user      = testuser,
                                             computing = demo_slurm_computing,
                                             data      = {'user': 'slurmtestuser'})


