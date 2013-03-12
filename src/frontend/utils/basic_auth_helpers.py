import base64

from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from frontend.utils.misc import is_embargoed
from frontend.utils.auth_helper import can_write, can_read

# snippet adapted from http://djangosnippets.org/snippets/243/

#############################################################################
#
def view_or_basicauth(view, request, realm = "", *args, **kwargs):
    """
    This is a helper function used by both 'logged_in_or_basicauth' and
    'has_perm_or_basicauth' that does the nitty of determining if they
    are already logged in or if they have provided proper http-authorization
    and returning the view if all goes well, otherwise responding with a 401.
    """
    siloname = None
    id = None
    if kwargs:
        siloname = kwargs.get('siloname',None)
        id = kwargs.get('id',None)

    if siloname:
        # basic authz check if user is logged in:
        if request.method in ["POST", "PUT", "DELETE"] and request.user.is_authenticated():
            if can_write(request.user, siloname, id):
                return view(request, *args, **kwargs)
            else:
                # Forbidden
                response = HttpResponse()
                response.status_code = 403
                return response
            
        if not is_embargoed(siloname, id) and request.method == "GET":
            # No need to log in to read
            return view(request, *args, **kwargs)
            

    # They are not logged in. See if they provided login credentials
    #
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2:
            # NOTE: We are only support basic authentication for now.
            #
            if auth[0].lower() == "basic":
                uname, passwd = base64.b64decode(auth[1]).split(':')
                user = authenticate(username=uname, password=passwd)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        request.user = user
                        return view(request, *args, **kwargs)

    # Either they did not provide an authorization header or
    # something in the authorization attempt failed. Send a 401
    # back to them to ask them to authenticate.
    #
    
    # If the request is "GET" and the item is under embargo, the view will generate
    # a tailored view. Unfortunately, this really mucks about with any REST implementation
    # Using a kludge parameter of 'force_auth' to force the 401 on a GET request... :(
    
    if request.method != "GET" or request.REQUEST.get("force_auth", None) != None:
        response = HttpResponse()
        response.status_code = 401
        response['WWW-Authenticate'] = 'Basic realm="%s"' % realm
        return response
    else:
        return view(request, *args, **kwargs)

    
#############################################################################
#
def logged_in_or_basicauth(realm = ""):
    """
    Use:

    @logged_in_or_basicauth('REALMNAME')
    def your_view:
        ...

    """
    def view_decorator(func):
        def wrapper(request, *args, **kwargs):
            return view_or_basicauth(func, request,
                                     realm, *args, **kwargs)
        return wrapper
    return view_decorator
