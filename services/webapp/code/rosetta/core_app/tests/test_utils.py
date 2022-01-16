import json

from django.contrib.auth.models import User
        
from .common import BaseAPITestCase
from ..utils import sanitize_container_env_vars

class TestUtils(BaseAPITestCase):

    def setUp(self):
        pass

    def test_sanitize_user_env_vars(self):
        '''Test sanitize use env vars''' 
        
        # Basic
        env_vars = {'myvar': 'a'}
        self.assertEqual(sanitize_container_env_vars(env_vars),env_vars)

        # Allowed specia
        env_vars = {'myvar': '/a_directory/a-test'}
        self.assertEqual(sanitize_container_env_vars(env_vars),env_vars)
        
        # Potential malicious
        env_vars = {'myvar': '$(rm -rf)'}
        with self.assertRaises(ValueError):
            sanitize_container_env_vars(env_vars)
            
        
         
        
        
        

