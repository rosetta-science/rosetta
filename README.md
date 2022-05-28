# Rosetta 🛰️


_A container-centric Science Platform_


Rosetta makes it easy to run graphical interactive workloads on batch and remote computing systems using Docker and Singularity containers.

Rosetta licensed under the Apache License 2.0, unless otherwise specificed.


## Quickstart

Requirements:
    
    Bash, Git and Docker. Runs on Linux, Mac or Windows*.

*Windows not fully supported in development mode due to lack of support for symbolic links.

Setup

	$ rosetta/setup

Build

    $ rosetta/build

Run

	$ rosetta/run


Populate demo data

    $ rosetta/populate
    # You can now point your browser to http://localhost:8080
    # Log in using "testuser@rosetta.platform""and password "testpass"
    # To run Slurm jobs, use partition name "partition1"

Clean

	# rosetta/clean

### Configuration

Webapp service configuraion parameters and their defaults:

      - SAFEMODE=false
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

 - `ROSETTA_REGISTRY_HOST` should be set to the same value as `ROSETTA_HOST` for production scenarios, in order to be secured unders SSL. The `standaloneworker` is configured to treat the following hosts (and ports) as unsecure registies, where it can connect without a valid certificate: `proxy:5000`,`dregistry:5000` and `rosetta.platform:5000`.
 - `ROSETTA_WEBAPP_HOST` is used for let the agent know where to connect, and it is differentiated from `ROSETTA_HOST` as it can be on an internal Docker network. It is indeed defaulted to the `webapp` container IP address.

Proxy service configuraion parameters and their defaults:

      - SAFEMODE=false
      - ROSETTA_HOST=localhost


### User types 
In Rosetta there are two user types: standard users and power users. Their type is set in their user profile, and only power users can:

   - set custom task passwords
   - choose task access methods other than the default one (bypassing HTTP proxy + auth)
   - add containers with interface protocols other than the HTTP
   


### Extras

List all running services

    # rosetta/ps

Check status (not yet fully supported)

    # rosetta/status



### Building errors

It is common for the build process to fail with a "404 not found" error on an apt-get instrucions, as apt repositories often change their IP addresses. In such case, try:

    $ rosetta/build nocache


### Development mode

Django development server is running on port 8080 of the "webapp" service.

To enable live code changes, add or comment out the following in docker-compose.yaml under the "volumes" section of the "webapp" service:

    - ./services/webapp/code:/opt/code
    
This will mount the code from services/webapp/code as a volume inside the webapp container itself allowing to make immediately effective codebase edits.

Note that when you edit the Django ORM model, you need to make migrations and apply them to migrate the database:

    $ rosetta/makemigrations
    $ rosetta/migrate


    
### Logs and testing

Run Web App unit tests (with Rosetta running)

    $ rosetta/logs webapp
    
    $ rosetta/logs webapp startup
    
    $ rosetta/logs webapp server
    
    $ rosetta/test
    
    
### Computing resources requirements

Ensure that computing resource have:

 - a container engine or wms available (of course);
 - Python installed and callable with the "python" executable or the agent will fail;
 - Bash as default shell for ssh-based computign resources.

    
## Known issues

    SINGULARITY_TMPDIR=/...
    .singularity in user home with limited space
    
    Some Docker versions (e.g. old-ish on Mac) do not let podman work due to fuse permissions
    SSH computing resources require python3 and wget installed, or will raise (empty) errors when submitting tasks. . Check 127 error codes.

