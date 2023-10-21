"""
TODO:
  - get/post/... path, maybe option.
  - rate-limit(throttle) option.
"""

from functools import wraps
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.urls.resolvers import URLPattern
from django.shortcuts import resolve_url
from django.urls import path
from django.contrib.auth.decorators import login_required, \
                                           permission_required # All permission(s)
from django.views.decorators.csrf import csrf_exempt


# Accessibility helper functions - Start

from django import template

register = template.Library()


@property
def is_user_admin(self):
    return self.type == self.TYPES.ADMIN


@property
def is_in_admin(self):
    return is_member(self, self.GROUPS.ADMIN)


@property
def is_overall_admin(self):
    return self.is_user_admin or self.is_in_admin


@register.filter(name='has_group')
def has_group(user, group):
    return is_member(user, group)


@register.filter(name='is_user_admin')
def is_user_admin(user):
    return user.is_user_admin


@register.filter(name='is_in_admin')
def is_in_admin(user):
    return user.is_in_admin


@register.filter(name='is_overall_admin')
def is_overall_admin(user):
    return user.is_overall_admin

# Accessibility helper functions - End


# Group checking functions section

def user_passes_group_test(test_func, login_url=None,
                           redirect_field_name=REDIRECT_FIELD_NAME, group=None):
    """
    Decorator for views that checks that the user passes the given test,
    redirecting to the log-in page if necessary. The test should be a callable
    that takes the user object and returns True if the user passes.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request.user, group=group):
                return view_func(request, *args, **kwargs)
            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            # If the login url is the same scheme and net location then just
            # use the path as the "next" url.
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    return decorator


def is_member(user, group):
    # Any group(s)
    if isinstance(group, str):
        group = (group,)
    return user.groups.filter(name__in=group).exists()


# Handy path functions section

def login_required_path(route, view, name=None, kwargs=None):
    return path(route, login_required(view), name, kwargs)


def csrf_exempt_path(route, view, name=None, kwargs=None):
    return path(route, csrf_exempt(view), name, kwargs)


def login_required_csrf_exempt_path(route, view, name=None, kwargs=None):
    return path(route, csrf_exempt(login_required(view)), name, kwargs)


# Handy (Permission) path functions section

def has_permission_path(permission, route, view, name=None, kwargs=None):
    return path(route, permission_required(permission)(view), name, kwargs)


def has_permission_login_required_path(permission, route, view, name=None, kwargs=None):
    return path(route, permission_required(permission)(login_required(view)),
                name, kwargs)


def has_permission_csrf_exempt_path(permission, route, view, name=None, kwargs=None):
    return path(route, csrf_exempt(permission_required(permission)(view)), name, kwargs)


def has_permission_login_required_csrf_exempt_path(permission, route, view,
                                                   name=None, kwargs=None):
    return path(route,
                csrf_exempt(permission_required(permission)(login_required(view))),
                name, kwargs)


# Handy (Group) path functions section

def has_group_path(group, route, view, name=None, kwargs=None):
    return path(route, user_passes_group_test(is_member, group=group)(view),
                name, kwargs)


def has_group_login_required_path(group, route, view, name=None, kwargs=None):
    return path(route,
                user_passes_group_test(is_member, group=group)(login_required(view)),
                name, kwargs)


def has_group_csrf_exempt_path(group, route, view, name=None, kwargs=None):
    return path(route,
                user_passes_group_test(is_member, group=group)(csrf_exempt(view)),
                name, kwargs)


def has_group_login_required_csrf_exempt_path(group, route, view,
                                              name=None, kwargs=None):
    return path(route,
    user_passes_group_test(is_member, group=group)(csrf_exempt(login_required(view))),
    name, kwargs)


# Control/Ultimate path function section

def controll_path(route, view, name=None,
                  is_login_required=False, is_csrf_exempt=False,
                  permission=None, group=None
                  , kwargs=None):
    # login_required
    if is_login_required:
        view = login_required(view)
    # csrf_exempt
    if is_csrf_exempt:
        view = csrf_exempt(view)
    # permission
    if permission:
        view = permission_required(permission)(view)
    # group
    if group:
        view = user_passes_group_test(is_member, group=group)(view)
    return path(route, view, name, kwargs)


# (Control/Ultimate) group-path function section

def group_path(urlpatterns, prefix_route='', paths=[], name='',
               is_login_required=False, is_csrf_exempt=False,
               permission=None, group=None):
    def make(path, prefix_route='', name='',
             effect_on_root_too=True, accesses=(None, None, None, None)
             ):
        name = f"{name}:{path.name}" if name else path.name
        
        route = str(
                prefix_route +
                str(
                    '/' if (not prefix_route.endswith('/') and
                            not path.pattern._route.startswith('/')) else ''
                )
                + path.pattern._route
            )
        route = route.strip('//')
        route = route.strip('/')
        route = route.replace('//', '/') + '/'
        
        path.name = name
        path.pattern._route = '' if route in ['', '/', '//'] else route
        
        if effect_on_root_too and any(accesses):
            login, csrf, perm, grp = accesses
            # login_required
            if login != None:
                path.callback = login_required(path.callback)
            # csrf_exempt
            if csrf != None:
                path.callback = csrf_exempt(path.callback)
            # permission
            if perm != None:
                path.callback = permission_required(perm)(path.callback)
            # group
            if grp != None:
                path.callback = user_passes_group_test(is_member,
                                                   group=grp)(path.callback)
        else:
            # login_required
            if is_login_required:
                path.callback = login_required(path.callback)
            # csrf_exempt
            if is_csrf_exempt:
                path.callback = csrf_exempt(path.callback)
            # permission
            if permission:
                path.callback = permission_required(permission)(path.callback)
            # group
            if group:
                path.callback = user_passes_group_test(is_member,
                                                   group=group)(path.callback)
        
        return path
    
    for path in filter(lambda path: path != None, paths):
        # path.default_args = path.default_args if type(path.default_args) == dict else {}
        
        inner_paths = path.default_args.get('paths', [])
        root_effect = path.default_args.get('root_effect', True)
        
        inner_is_login_required = path.default_args.get('is_login_required', None)
        inner_is_csrf_exempt = path.default_args.get('is_csrf_exempt', None)
        inner_permission = path.default_args.get('permission', None)
        inner_group = path.default_args.get('group', None)
        
        path.default_args = {}
        
        if type(path) == URLPattern:
            urlpatterns.append(
                make(path, prefix_route, name,
                effect_on_root_too=root_effect,
                accesses=(
                        inner_is_login_required,
                        inner_is_csrf_exempt,
                        inner_permission,
                        inner_group
                    )
                )
            )
        if inner_paths != []:
            """
            Nested routes in:
                name
                route
                accesses and ...
            """
            
            del path.default_args['paths'] # For Error: got an unexpected keyword.
            
            """
            When we are here, the path is already nested because
            it's been changed in the make function.
            """
            
            # login_required
            if inner_is_login_required != None:
                is_login_required = inner_is_login_required
            # csrf_exempt
            if inner_is_csrf_exempt != None:
                is_csrf_exempt = inner_is_csrf_exempt
            # permission
            if inner_permission != None:
                permission = inner_permission
            # group
            if inner_group != None:
                group = inner_group
            
            name = path.name
            prefix_route = path.pattern._route
            group_path(urlpatterns=urlpatterns,
                       prefix_route=prefix_route,
                       paths=inner_paths,
                       name=name,
                       # Accesses
                       is_login_required=is_login_required,
                       is_csrf_exempt=is_csrf_exempt,
                       permission=permission,
                       group=group)


"""
# Example:
group_path(urlpatterns, 'group/', [
    path('', views.group_index, name='index'),
    path('other/', views.other, name='other', kwargs={'paths': [
        path('inner/', views.inner, name='inner')
    ],
    'is_login_required': None,
    'is_csrf_exempt': None,
    'permission': None,
    'group': None,
    'root_effect': True # Default
    }),
], name='group', is_login_required=True, is_csrf_exempt=True, group='group-name-in-database-related-to-user')

# Output:
. group/ [name='group:index']
. group/other/ [name='group:other']
. group/other/inner/ [name='group:other:inner']
"""
