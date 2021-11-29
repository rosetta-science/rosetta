from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from ...models import Profile, Container, Computing, Storage, KeyPair, Page

class Command(BaseCommand):
    help = 'Adds the admin superuser with \'a\' password.'

    def handle(self, *args, **options):


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
            Profile.objects.create(user=testuser, auth='local', authtoken='129aac94-284a-4476-953c-ffa4349b4a50')

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
        #  Default home page
        #=====================
        default_home_page_content = '''
<header id="top" class="header">
    <div style="display:table-row">
        <div class="text-vertical-center">
            <h1>&nbsp;&nbsp;Rosetta <img src="/static/img/emoji_u1f6f0.png" style="height:84px; width:64px; padding-bottom:20px"></h1>
            <h2 style="margin-top:10px; margin-left:25px; margin-right:25px; font-weight:100; line-height: 30px;"><i>A container-centric Science Platform<br></i></h2>
        </div>
    </div>   
    <div class="container">
        <div class="dashboard">
            <div class="span8 offset2" style="margin: 30px auto; max-width:800px">
                Welcome to Rosetta!
                <br/><br/>
                This is the default main page content loaded after populating the platform with the default/demo data.
                To change it, head to the <a href="/admin">admin</a> section and edit the <code>Page</code> model with id "main".
                <br/><br/>
                A test user with admin rights registered with email <code>testuser@rosetta.platform</code> and password 
                <code>testpass</code> has been created as well, which you can use to login on the menu on the right and give Rosetta
                immediately a try. If you are using the default docker-compose file (i.e. you just ran <code>rosetta/setup</code>),
                then you will also have a few demo computing and storage resources (beside the internal one) already available
                and that you can play with, including a small Slurm cluster. Otherwise, you will need to setup your own ones
                from the <a href="/admin">admin</a> section.
                <br />
                <br />
                You can also create custom pages and access them under <code>/pages/page_id</code> should you need to provide
                your users informations about the platform and its storage and computing resources. For example, see this
                demo extra <a href="/pages/help">help page</a>. 
            </div>
        </div>
    </div>          
</header>
'''
        home_page = Page.objects.filter(id='main')
        if home_page:
            print('Not creating default main page content as already present')
        else:
            print('Creating default main page content...')
            Page.objects.create(id='main', content=default_home_page_content)

        extra_help_page_content = '''
<h1>Help!</h1>
<hr>
<p>
This is a demo extra page (a help page, in this case). Here you could for example provide the instructions on how to set up SSH-based 
computing resources using user keys, or who to contact to join a specific group to access its software and computing resources.
</p>

<p>
In general, the part of the URL following the <code>/pages/</code> path is parsed as the page id, 
so that if a page with that id exists in the database, its content will show up here.
You can use this system for creating a mini-website inside the platform 
to provide help, news and informations on your deployment. Or you can just ignore the whole thing and leave a plain logo in the main page. 
</p>
'''

        extra_help_page = Page.objects.filter(id='help')
        if home_page:
            print('Not creating extra help page content as already present')
        else:
            print('Creating extra help page content...')
            Page.objects.create(id='help', content=extra_help_page_content)



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
                                     name     = 'Minimal Desktop',
                                     description = 'A minimal desktop environment providing basic window management functionalities and a terminal.',
                                     registry = 'docker.io',
                                     image_name = 'sarusso/minimaldesktop',
                                     image_tag  = 'v0.2.0',
                                     image_arch = 'amd64',
                                     image_os   = 'linux',
                                     interface_port      = '8590',
                                     interface_protocol  = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True)

            # Basic Desktop
            Container.objects.create(user     = None,
                                     name     = 'Basic Desktop',
                                     description = 'A basic desktop environment. Provides a terminal, a file manager, a web browser and other generic applications.',
                                     registry = 'docker.io',
                                     image_name = 'sarusso/basicdesktop',
                                     image_tag  = 'v0.2.0',
                                     image_arch = 'amd64',
                                     image_os   = 'linux',
                                     interface_port      = '8590',
                                     interface_protocol  = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True,
                                     interface_auth_user = None)
 
 
            # Jupyter Notebook
            Container.objects.create(user     = None,
                                     name     = 'Jupyter Notebook',
                                     description = 'A Jupyter Notebook server',
                                     registry = 'docker.io',
                                     image_name = 'sarusso/jupyternotebook',
                                     image_tag  = 'v0.2.0',
                                     image_arch = 'amd64',
                                     image_os   = 'linux',
                                     interface_port      = '8888',
                                     interface_protocol  = 'http',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True,
                                     interface_auth_user = None)

            # Official Jupyter containers
            for tag in ['lab-3.2.2', 'lab-3.1.17']:
                
                Container.objects.create(user     = None,
                                         name     = 'Jupyter Data Science Lab',
                                         description = 'The official Jupyter Lab. The Data Science variant, which includes libraries for data analysis from the Julia, Python, and R communities.',
                                         registry = 'docker.io',
                                         image_name = 'jupyter/scipy-notebook',
                                         image_tag  = tag,
                                         image_arch = None,
                                         image_os   = None,
                                         interface_port      = '8888',
                                         interface_protocol  = 'http',
                                         interface_transport = 'tcp/ip',
                                         supports_custom_interface_port = True,
                                         supports_interface_auth = True)
                
                for arch in ['amd64', 'arm64']:
                    Container.objects.create(user     = None,
                                             name     = 'Jupyter Lab',
                                             description = 'The official Jupyter Lab. The Scipy variant, which includes popular packages from the scientific Python ecosystem.',
                                             registry = 'docker.io',
                                             image_name = 'jupyter/scipy-notebook',
                                             image_tag  = tag,
                                             image_arch = arch,
                                             image_os   = 'linux',
                                             interface_port      = '8888',
                                             interface_protocol  = 'http',
                                             interface_transport = 'tcp/ip',
                                             supports_custom_interface_port = True,
                                             supports_interface_auth = True)


            # SSH server
            Container.objects.create(user     = None,
                                     name     = 'SSH server',
                                     description = 'An SSH server supporting X forwarding as well.',
                                     registry = 'docker.io',
                                     image_name = 'sarusso/ssh',
                                     image_tag  = 'v0.2.0',
                                     image_arch = 'amd64',
                                     image_os   = 'linux',
                                     interface_port     = '22',
                                     interface_protocol = 'ssh',
                                     interface_transport = 'tcp/ip',
                                     supports_custom_interface_port = True,
                                     supports_interface_auth = True,
                                     interface_auth_user = 'metauser')

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
                                     container_runtimes = ['docker'])

            
            # Demo standalone computing plus conf
            demo_singlenode_computing = Computing.objects.create(name = 'Demo Standalone',
                                                                 description = 'A demo standalone computing resource.',
                                                                 type = 'standalone',
                                                                 access_mode = 'ssh+cli',
                                                                 auth_mode = 'user_keys',
                                                                 wms = None,
                                                                 conf = {'host': 'standaloneworker'},
                                                                 container_runtimes = ['singularity','podman'])
    
            # Add testuser extra conf for this computing resource
            testuser.profile.add_extra_conf(conf_type = 'computing_user', object=demo_singlenode_computing, value= 'testuser')

            #  Demo cluster computing plus conf
            demo_slurm_computing = Computing.objects.create(name = 'Demo Cluster',
                                                            description = 'A demo cluster computing resource.',
                                                            type = 'cluster',
                                                            access_mode = 'ssh+cli',
                                                            auth_mode = 'user_keys',
                                                            wms = 'slurm',
                                                            conf = {'host': 'slurmclustermaster', 'default_partition': 'partition1'},
                                                            container_runtimes = ['singularity'])
           
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
 





