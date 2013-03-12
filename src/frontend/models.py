from django.db import models
from django.contrib.auth.models import User

# Authz helpers
from utils.auth_helper import is_administrator, is_manager, is_submitter, get_auth_context

# Add any user specific fields to this, and all User-objects will have a 'get_profile()' method
# that you can use to retrieve this set of data.
# NB use the 'profile' property being added to the User object, as this will create a profile
# if one does not already exist. The 'get_profile()' method will fail if a profile does not exist
# (and is therefore always safe, but might throw an exception if user has no profile set up.)

class UserProfile(models.Model):
    user = models.ForeignKey(User, unique=True)
    name = models.CharField(max_length=70, blank=True)

class Silo(models.Model):
    silo = models.CharField(max_length=50)

class Dataset(models.Model):
    silo = models.ForeignKey(Silo, unique=False)
    name = models.CharField(max_length=100, blank=True)

# Create the profile on reference
User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])

# Some shorthand properties:
User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])

# Some authz shorthand methods:
# eg:
#     ... [in a view method:]
#     request.user.is_ROLE(siloname)  ==> True if user is superuser or has ROLE for the 
#                                         given silo, False otherwise.
#     request.user.is_ROLE()          ==> True if user is superuser or has ROLE in ANY silo,
#                                         False otherwise.
User.is_administrator = lambda u, siloname=None: is_administrator(u.username, siloname)
User.is_manager = lambda u, siloname=None: is_manager(u.username, siloname)
User.is_submitter = lambda u, siloname=None: is_submitter(u.username, siloname)

# Context helper, returning a dict with relevant authz flags 
# eg ({"administrator":True, ..} etc)
User.get_auth_context = lambda u, siloname=None: get_auth_context(u, siloname)
