from django import template

register = template.Library()


@register.filter
def get_item(value, key):
    if isinstance(value, dict):
        return value.get(key)
    return None


@register.filter
def yesno_icon(value):
    return 'Yes' if value else 'No'
