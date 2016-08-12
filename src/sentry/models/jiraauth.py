from __future__ import absolute_import

from django.db import models

from sentry.db.models import Model


class JiraAuth(Model):
    __core__ = False
    client_key = models.CharField(max_length=50, unique=True)
    shared_secret = models.CharField(max_length=100)
    base_url = models.CharField(max_length=60)
    public_key = models.CharField(max_length=250)

    class Meta:
        app_label = 'sentry'
        db_table = 'sentry_jira_auth'
