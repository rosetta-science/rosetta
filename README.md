# Rosetta 🛰️

Rosetta is a science platform for resource-intensive, interactive data analysis which runs user tasks as software containers.

It is built on top of a novel architecture based on framing user tasks as microservices – independent and self-contained units – which allows to fully support custom and user-defined software packages, libraries and environments. These include complete remote desktop and GUI applications, common analysis environments as the Jupyter Notebooks, and more.

Rosetta relies on Open Container Initiative containers, which allow for safe, effective and reproducible code execution; can use a number of container engines and runtimes; and seamlessly supports several workload management systems, thus enabling containerized workloads on a wide range of computing resources.

More information can be found in the paper "[Rosetta: A container-centric science platform for resource-intensive, interactive data analysis](https://www.sciencedirect.com/science/article/pii/S2213133722000634)".

This work is licensed under the Apache License 2.0, unless otherwise specified.




## Quickstart

Requirements:
    
    Bash, Git and Docker. Runs on Linux, Mac or Windows*.

*Windows not fully supported in development mode due to lack of support for symbolic links.

Inizialize

	$ cp docker-compose-dev.yml docker-compose.yml

Build

    $ rosetta/build

Run

	$ rosetta/run

List running services

    # rosetta/ps

Populate demo data

    $ rosetta/populate
    # You can now point your browser to http://localhost:8080
    # Log in using "testuser@rosetta.platform""and password "testpass"
    # To run Slurm jobs, use partition name "partition1"

Clean

	# rosetta/clean


## Configuration

### Webapp

These are the webapp service configuration parameters and their defaults:

      - SAFEMODE=false
      - DJANGO_DB_ENGINE="django.db.backends.postgresql_psycopg2"
      - DJANGO_DB_NAME="rosetta"
      - DJANGO_DB_USER="rosetta_master"
      - DJANGO_DB_PASSWORD="949fa84a"
      - DJANGO_DB_HOST="postgres"
      - DJANGO_DB_PORT=5432
      - DJANGO_DEV_SERVER=true
      - DJANGO_DEBUG=true
      - DJANGO_LOG_LEVEL=ERROR
      - ROSETTA_LOG_LEVEL=ERROR
      - ROSETTA_HOST=localhost      
      - ROSETTA_TASKS_PROXY_HOST=$ROSETTA_HOST
      - ROSETTA_TASKS_TUNNEL_HOST=$ROSETTA_HOST  
      - ROSETTA_WEBAPP_HOST=""
      - ROSETTA_WEBAPP_PORT=8080
      - ROSETTA_REGISTRY_HOST=proxy
      - ROSETTA_REGISTRY_PORT=5000
      - DJANGO_EMAIL_SERVICE=Sendgrid
      - DJANGO_EMAIL_APIKEY=""
      - DJANGO_EMAIL_FROM="Rosetta <notifications@rosetta.local>"
      - INVITATION_CODE=""
      - OIDC_RP_CLIENT_ID=""
      - OIDC_RP_CLIENT_SECRET=""
      - OIDC_OP_AUTHORIZATION_ENDPOINT=""
      - OIDC_OP_TOKEN_ENDPOINT=""
      - OIDC_OP_JWKS_ENDPOINT=""
      - DISABLE_LOCAL_AUTH=false

Notes:

 - `ROSETTA_REGISTRY_HOST` should be set to the same value as `ROSETTA_HOST` for production scenarios, in order to be secured under SSL. The `standaloneworker` is configured to treat the following hosts (and ports) as insecure registries, where it can connect without a valid certificate: `proxy:5000`,`dregistry:5000` and `rosetta.platform:5000`.
 - `ROSETTA_WEBAPP_HOST` is used for let the agent know where to connect, and it is differentiated from `ROSETTA_HOST` as it can be on an internal Docker network. It is indeed defaulted to the `webapp` container IP address.


### Proxy

These aere the proxy service configuration parameters and their defaults:

      - SAFEMODE=false
      - ROSETTA_HOST=localhost
      - ROSETTA_TASKS_PROXY_HOST=$ROSETTA_HOST

Certificates can be automatically handled with Letsencrypt. By default, a snakeoil certificate is used. To set up Letsencrypt, you need to run the following commands inside the proxy service (once in its lifetime).

    $ rosetta/shell proxy

First of all remove the default snakeoil certificates:

	$ sudo rm -rf /etc/letsencrypt/live/YOUR_ROSETTA_HOST (or ROSETTA_TASKS_PROXY_HOST)

Then:

    $ nano /etc/apache2/sites-available/proxy-global.conf
    
...and change the certificates for the domain that you want to enable with Letsencrypt to use the snakeoils located in `/root/certificates/` as per the first lines of the `proxy-global.conf` file (otherwise next command will fail).

Now restart apache to pick up the new snakeoils:

	$  sudo apache2ctl -k graceful

Lastly, tell certbot to generate and validate certificates for the domain:

    $ sudo certbot certonly --apache --register-unsafely-without-email --agree-tos -d YOUR_ROSETTA_HOST (or ROSETTA_TASKS_PROXY_HOST)
    
This will initialize the certificates in /etc/letsencypt, which are stored on the host in `./data/proxy/letsencrypt`

Finally, re-run the proxy service to drop the temporary changes and pick up the new, real certificates:

    $ rosetta/rerun proxy


### User types 
In Rosetta there are two user types: standard users and power users. Their type is set in their user profile, and only power users can:

   - set custom task passwords
   - choose task access methods other than the default one (bypassing HTTP proxy + auth)
   - add containers with interface protocols other than the HTTP
   
     
### Computing resources

When configuring computing resources, ensure that they have:

 - a container engine or wms available (of course);
 - Python installed and callable with the "python" executable or the agent will fail;
 - Bash as default shell for ssh-based computing resources.



## Development

### Live code changes

Django development server is running on port 8080 of the "webapp" service.

To enable live code changes, add or comment out the following in docker-compose.yaml under the "volumes" section of the "webapp" service:

    - ./services/webapp/code:/opt/code
    
This will mount the code from services/webapp/code as a volume inside the webapp container itself allowing to make immediately effective codebase edits.

Note that when you edit the Django ORM model, you need to make migrations and apply them to migrate the database:

    $ rosetta/makemigrations
    $ rosetta/migrate


### Testing

Run Web App unit tests (with Rosetta running)
    
    $ rosetta/test


### Logs


Check out logs for Docker containers (including entrypoints):


    $ rosetta/logs web

    $ rosetta/logs proxy


Check out logs for supervisord services:

        
    $ rosetta/logs web startup
    
    $ rosetta/logs web server

    $ rosetta/logs proxy apache
    
    $ rosetta/logs proxy certbot

    
## Known issues

### Building errors

It is common for the build process to fail with a "404 not found" error on an apt-get instructions, as apt repositories often change their IP addresses. In such case, try:

    $ rosetta/build nocache
    
### Singularity issues

- Singularity has several issues, in particular the `.singularity` in user home might have limited space. Consider setting the `SINGULARITY_TMPDIR=/tmp/$USER` env var. 
- Some Docker versions (e.g. old-ish on Mac) do not let Podman work due to fuse permissions.
- Computing resources require python3 and curl installed for the agent to work, or will raise (empty) errors when submitting tasks. Check 127 error codes.

