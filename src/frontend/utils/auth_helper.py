# -*- coding: utf-8 -*-
"""
Copyright (c) 2012 University of Oxford

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, --INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import logging
log = logging.getLogger(__name__)

from django.contrib.auth.models import User, Group

from frontend.utils.misc import is_embargoed, NotASilo
from frontend.utils.filestore import granary

ALLDATA=2
MDONLY=1

def group_name(siloname, role):
    # FIXME: Assumes siloname and role aren't complex strings
    # Failing edge cases are possible
    if role == u"superuser":
        return u"superuser"
    return u"%s.%s" % (siloname, role)

def silo_role_from_group(group_name):
    # FIXME: Assumes siloname and role aren't complex strings
    # Failing edge cases are possible
    if group_name == u"superuser":
        return (None, u"superuser")
    s = group_name.rsplit(".", 1)
    if len(s) == 2:
        return s
    else:
        log.error("FATAL: Group name '%s' was not parsable into silo and role" % group_name)
        return

def is_superuser(username):
    try:
        u = User.objects.get(username=username)
        return u.is_superuser
    except User.DoesNotExist:
        log.error(u"User %s doesn't exist" % username)
    return False

def has_role(username, role, siloname = None):
    try:
        u = User.objects.get(username=username)
        if u.is_superuser:
            return True
        if siloname:
            auth_tag = group_name(siloname, role)
            if u.groups.filter(name__exact=auth_tag).exists():
                return True
        else:
            if u.groups.filter(name__endswith=role).exists():
                return True
    except User.DoesNotExist:
        log.error(u"User %s doesn't exist" % username)
    return False

def is_administrator(username, siloname):
    return has_role(username, u"administrator", siloname)
    
def is_manager(username, siloname):
    return has_role(username, u"manager", siloname)
    
def is_submitter(username, siloname):
    return has_role(username, u"submitter", siloname)

def is_creator(username, siloname, id):
    if granary.issilo(siloname):
        silo = granary.get_rdf_silo(siloname)
        if silo.exists(id):
            item = silo.get_item(id)
            if item.manifest and item.manifest.state and 'metadata' in item.manifest.state and item.manifest.state['metadata'] and \
                'createdby' in item.manifest.state['metadata'] and item.manifest.state['metadata']['createdby']:
                return (username == item.manifest.state['metadata']['createdby'])
    return False

def can_anonymous_read(siloname, id=None):
    # if silo/id object is not under embargo, return true
    if granary.issilo(siloname):
        silo = granary.get_rdf_silo(siloname)
        if not is_embargoed(silo, id):
            # Not embargoed, so files+md readable
            return True
        else:
            return False

def can_read(user, siloname, id=None):
    # if silo/id object is not under embargo, return true
    # else if user is admin/manager or creator of id then all is visible
    # otherwise, just show MD (or nothing if repository set to block MD)
    if granary.issilo(siloname):
        if can_anonymous_read(siloname, id):
            return ALLDATA
        else:
            if user.is_authenticated():
                if user.is_administrator(siloname) or user.is_manager(siloname):
                    return ALLDATA
                elif user.is_submitter(siloname):
                    if id == None or is_creator(user.username, siloname, id):
                        # submitter to repository - allow read to silo contents
                        return ALLDATA
            return MDONLY
    else:
        raise NotASilo()

def can_list_silo(user, siloname):
    # if user is admin/manager/submitter or creator of id then okay
    if granary.issilo(siloname):
        if can_anonymous_read(siloname, id):
            return ALLDATA
        else:
            if user.is_authenticated():
                if user.is_administrator(siloname) or user.is_manager(siloname) or is_creator(user.username, siloname, id):
                    return ALLDATA
            return MDONLY
    else:
        raise NotASilo()

def can_write(user, siloname, id=None):
    # False if not authenticated 
    # True if admin/manager
    # or True if submitter AND creator of id
    # or True if submitter and no id is given (ie silo rights)
    # else False
    if not user.is_authenticated():
        return False
    if granary.issilo(siloname):
        if user.is_administrator(siloname) or user.is_manager(siloname):
            return True
        elif user.is_submitter(siloname):
            if id == None:
                return True
            elif is_creator(user.username, siloname, id):
                return True
        return False
    else:
        raise NotASilo()

def basic_has_perm(user, request, siloname, id):
    if request.method == "GET":
        # idempotent READ
        return can_read(user, siloname, id)
    elif request.method in ["POST", "PUT", "DELETE"]:
        return can_write(user, siloname, id)

def get_auth_context(user_obj, siloname):
    # Cache in the user session? Dangerous perhaps but quicker?
    if user_obj.is_superuser:
        return {'administrator':True,
                'manager':True,
                'submitter':True,
                'superuser':True,
                'user_logged_in':True}
    # Assuming numbers of submitters > Administrators >= managers
    username = user_obj.username
    if is_submitter(username, siloname):
        return {'administrator':False,
                'manager':False,
                'submitter':True,
                'superuser':False,
                'user_logged_in':True}
    if is_administrator(username, siloname):
        return {'administrator':True,
                'manager':True,
                'submitter':True,
                'superuser':False,
                'user_logged_in':True}
    if is_manager(username, siloname):
        return {'administrator':False,
                'manager':True,
                'submitter':True,
                'superuser':False,
                'user_logged_in':True}

    return {'administrator':False,
            'manager':False,
            'submitter':False,
            'superuser':False,
            'user_logged_in':True}
