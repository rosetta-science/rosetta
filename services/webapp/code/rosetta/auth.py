from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.views import OIDCAuthenticationCallbackView
from .core_app.utils import finalize_user_creation
from django.http import HttpResponseRedirect

# Setup logging
import logging
logger = logging.getLogger(__name__)


class RosettaOIDCAuthenticationBackend(OIDCAuthenticationBackend):

    def create_user(self, claims):

        # Call parent user creation function
        user = super(RosettaOIDCAuthenticationBackend, self).create_user(claims)

        # Add profile, keys etc.
        finalize_user_creation(user, auth='oidc')

        return user

    def get_userinfo(self, access_token, id_token, payload):

        # Payload must contain the "email" key
        return payload


class RosettaOIDCAuthenticationCallbackView(OIDCAuthenticationCallbackView):

    def login_success(self):

        # Call parent login_success but do not return
        super(RosettaOIDCAuthenticationCallbackView, self).login_success()

        logger.debug('Trying to get cookie-based post login redirect')
        post_login_page = self.request.COOKIES.get('post_login_redirect')
        if post_login_page:
            logger.debug('Got "%s" and redirecting', post_login_page )
            response = HttpResponseRedirect(post_login_page)
            response.delete_cookie('post_login_redirect')
            return response
        else:
            logger.debug('No cookie-based post login redirect found, redirecting to "%s"', self.success_url)
            return HttpResponseRedirect(self.success_url)


