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

# HTTP Method restriction
from django.views.decorators.http import require_http_methods, require_safe
from django.http import Http404, HttpResponse, HttpResponseForbidden

from django.core.urlresolvers import reverse
from django.shortcuts import redirect

# Mako templating engine
from djangomako.shortcuts import render_to_response, render_to_string

import settings

import json

from utils.filestore import granary
from utils.redis_helper import b
from utils.file_unpack import check_file_mimetype, BadZipfile, get_zipfiles_in_dataset, unpack_zip_item, read_zipfile

from utils.misc import create_new, allowable_id2, NotASilo

from utils.auth_entry import list_silos, get_datasets_count, authz, add_auth_info_to_context, list_user_permissions, \
                             add_dataset, delete_dataset, get_datasets

from utils.basic_auth_helpers import logged_in_or_basicauth

from utils.auth_helper import ALLDATA, MDONLY, can_read, can_write

from utils.conneg import render_html_or_json
from utils.bag import create_context

import logging
log = logging.getLogger(__name__)

@logged_in_or_basicauth('DATABANK')
def silo_view(request, siloname):
    """
GET: Obtain a list of datasets in a silo

Returns
401 if not a valid user
403 if not authorized
Accept:text/html
Returns the ids of each dataset in the silo, along with a form for changing the embargo information and deleting the dataset. A form for dataset creation is also available.
Accept: text/plain, application/json
200 OK
Returns a JSON-encoded list of dataset ids in that silo along with the embargo information for each dataset
The file datasetsInSiloInformation.txt contains an example of the data returned (data_returned)
Accept:*/*, default
Returns text/HTML listing the ids of each dataset, along with a form for changing the embargo information and deleting the dataset. A form for dataset creation is also available.
    """
    if not granary.issilo(siloname):
        # No silo here
        response = HttpResponse()
        response.status_code = 404
        return response
        
    # Deal with request methods - GET then POST
    if request.method == "GET":
        c = create_context(request.user)
        
        c.silo_name = siloname

        # FIXME: Make these unhardcoded
        if siloname in ['ww1archives', 'digitalbooks']:
            abort(501, "The silo %s contains too many data packages to list"%siloname)
        c.editor = False
        
        c.read_state = can_read(request.user, siloname)
        
        if state == MDONLY:
            if settings.METADATA_EMBARGOED:
                # Forbidden
                response = HttpResponse()
                response.status_code = 403
                return response

        if can_write(request.user, siloname):
            c.editor = True

        options = request.REQUEST
        c.start = 0
        if 'start' in options and options['start']:
            try:
                c.start = int(options['start'])
            except ValueError:
                c.start = 0
        c.rows = 100
        if 'rows' in options and options['rows']:
            try:
                c.rows = int(options['rows'])
            except ValueError:
                c.rows = 100
                
                     
        c_silo = granary.get_rdf_silo(siloname)
        # Get title of silo
        state_info = granary.describe_silo(siloname)
        if 'title' in state_info and state_info['title']:
            c.title = state_info['title']
        # Get number of data packages in silo
        numFound = get_datasets_count(siloname)
        try:
            c.numFound = int(numFound)
        except ValueError:
            c.numFound = 0

        c.embargos = {}
        # FIXME: A crushingly slow way to check?
        for item in get_datasets(siloname, start=c.start, rows=c.rows):
            try:
                c.embargos[item] = is_embargoed(c_silo, item)
            except:
                c.embargos[item] = None
        c.items = c.embargos.keys()
        
        # pagination
        c.permissible_offsets = []
        c.pages_to_show = 5
        try:
            remainder = c.numFound % c.rows
            if remainder > 0:
                c.lastPage = c.numFound - remainder
            else:
                c.lastPage = c.numFound - c.rows

            if c.numFound > c.rows:
                offset_start = c.start - ( (c.pages_to_show/2) * c.rows )
                if offset_start < 0:
                    offset_start = 0
   
                offset_end = offset_start + (c.pages_to_show * c.rows)
                if offset_end > c.numFound:
                    offset_end = c.numFound
                    if remainder > 0:
                        offset_start = c.lastPage - (c.pages_to_show * c.rows)
                    else:
                        offset_start = c.lastPage - ((c.pages_to_show-1) * c.rows)

                    if offset_start < 0:
                        offset_start = 0
                              
                c.permissible_offsets = list( xrange( offset_start, offset_end, c.rows) )
        except ValueError:
            # FIXME: Not a good solution, escaping here
            pass
            
        return render_html_or_json(request, c, '/siloview.html', c.embargos)
    elif request.method == "POST":
        """
POST: Create new dataset

Parameters
id	 {id to create}
embargoed	 {true|false} (optional).
If the parameter is not supplied, a default value of true will be used.
embargoed_until	 {ISO8601 date} (optional).
If embargoed = true and no date has been supplied, a default time delta of 70 years will be used
title	{(Optional)}
Returns
409 if dataset already exists 
401 If not a valid user 
403 if not authorized 
403 if the name of the dataset does not confirm to the naming rule (name can contain only the followin characters 0-9a-zA-Z-_:
Accept: text/html
302 to splash page for newly created dataset
Accept: text/plain, application/json
201 created
Accept: */*, default
Returns text/plain, 201 created
PUT, DELETE: NOOP
        """
                
        if not can_write(request.user, siloname):
            # Forbidden
            response = HttpResponse()
            response.status_code = 403
            return response
        else:
            params = request.POST.dict()

            if not params.has_key("id"):
                response = HttpResponse()
                response.status_code = 400
                response.content = "400 Bad Request: Parameter 'id' is not available"
                return response
                
            c_silo = granary.get_rdf_silo(siloname)        
            if c_silo.exists(params['id']):
                response = HttpResponse()
                response.status_code = 409
                response.content = "409 Conflict: Data package already exists"
                return response

            # Supported params:
            # id, title, embargoed, embargoed_until, embargo_days_from_now
            id = params['id']
            if not allowable_id2(id):
                response = HttpResponse()
                response.status_code = 400
                response.content = "400 Bad request. Data package name not valid"
                return response

            del params['id']
            item = create_new(c_silo, id, request.user.username, **params)
            add_dataset(siloname, id)
            # Broadcast change as message
            try:
                b.creation(siloname, id, ident=request.user.username)
            except:
                pass
                 
            # conneg return
            
            if "HTTP_ACCEPT" in request.META.keys():
                if str(request.META['HTTP_ACCEPT']).lower() in ["text/html", "text/xhtml"]:
                    redirect('datasets_main_view', siloname=siloname, id=id)
            
            response = HttpResponse()
            response.status_code = 201
            response.content = "201 Created"
            response['Content-Location'] = reverse('datasets_main_view', siloname=siloname, id=id)
            return response
    
def dataset_view(request, siloname, id):
    return HttpResponse(siloname+" "+id, mimetype="text/plain")
    
def item_view(request, siloname, id, path):
    return HttpResponse(siloname+" "+id+" - "+path, mimetype="text/plain")
