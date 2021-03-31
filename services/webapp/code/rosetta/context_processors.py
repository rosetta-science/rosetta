import os
from django.conf import settings
def export_vars(request):
    data = {}
    
    # Set open id connect enabled or not
    if settings.OIDC_RP_CLIENT_ID:
        data['OPENID_ENABLED'] = True
    else:
        data['OPENID_ENABLED'] = False
    
    # Set invitation code required or not
    if settings.INVITATION_CODE:
        data['INVITATION_CODE_ENABLED'] = True
    else:
        data['INVITATION_CODE_ENABLED'] = False   
              
    return data