from django import template

register = template.Library()

@register.simple_tag
def is_computing_configured(computing, user):
    return computing.manager.is_configured_for(user)


# {% is_computing_configured computing user %}
