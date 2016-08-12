import hashlib
import json

import jwt
from six.moves.urllib.parse import quote

from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.utils.decorators import method_decorator

from sentry.models import JiraAuth
from sentry.web.helpers import render_to_response


CONNECT_JSON = """
{
     "name": "Hello World",
     "description": "Atlassian Connect add-on",
     "key": "com.example.myaddon",
     "baseUrl": "",
     "vendor": {
         "name": "Example, Inc.",
         "url": "http://example.com"
     },
     "authentication": {
         "type": "jwt"
     },
     "lifecycle": {
         "installed": "/jira-installed-callback"
     },
     "apiVersion": 1,
     "modules": {
        "jiraProjectTabPanels": [
            {
                "key": "my-requests-link",
                "name": {
                    "value": "My Requests"
                },
                "url": "/jira-ui-plugin/"
            }
        ]
     }
 }
"""

class JiraUIWidgetView(View):
    def _quote(self, val):
        # see https://en.wikipedia.org/wiki/Percent-encoding
        return quote(val).replace('%7E', '~').replace('/', '%2F')

    def get_query_hash(self, request):
        # see https://developer.atlassian.com/static/connect/docs/latest/concepts/understanding-jwt.html#qsh
        query_params = request.GET
        method = request.method.upper()
        uri = request.path.rstrip('/')
        sorted_query = []

        for k, v in sorted(query_params.items()):
            if k != 'jwt':
                if isinstance(v, list):
                    param_val = [self._quote(val) for val in v].join(',')
                else:
                    param_val = self._quote(v)
                sorted_query.append('%s=%s' % (self._quote(k), param_val))

        query_string = '%s&%s&%s' % (method, uri, '&'.join(sorted_query))
        return hashlib.sha256(query_string.encode('utf8')).hexdigest()

    def get(self, request, *args, **kwargs):
        # https://developer.atlassian.com/static/connect/docs/latest/concepts/authentication.html
        # Extract the JWT token from the request's jwt query
        # parameter or the authorization header.
        token = request.GET['jwt']
        # Decode the JWT token, without verification. This gives
        # you a header JSON object, a claims JSON object, and a signature.
        decoded = jwt.decode(token, verify=False)
        # Extract the issuer ('iss') claim from the decoded, unverified
        # claims object. This is the clientKey for the tenant - an identifier
        # for the Atlassian application making the call
        issuer = decoded['iss']
        # Look up the sharedSecret for the clientKey, as stored
        # by the add-on during the installation handshake
        jira_auth = JiraAuth.objects.get(client_key=issuer)
        # Verify the signature with the sharedSecret and
        # the algorithm specified in the header's alg field.
        decoded_verified = jwt.decode(token, jira_auth.shared_secret)
        # Verify the query has not been tampered by Creating a Query Hash
        # and comparing it against the qsh claim on the verified token.
        if self.get_query_hash(request) != decoded_verified['qsh']:
            return HttpResponseBadRequest()
        res = render_to_response('sentry/jira_ui_widget.html', {}, request)
        res['X-Frame-Options'] = 'ALLOW-FROM https://getsentry-dev.atlassian.net/'
        res['Content-Security-Policy'] = 'frame-ancestors https://getsentry-dev.atlassian.net/'
        return res


class JiraConfigView(View):
    def get(self, request, *args, **kwargs):
        return HttpResponse(CONNECT_JSON, content_type='application/json')


class JiraInstalledCallback(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(JiraInstalledCallback, self).dispatch(request, *args, **kwargs)

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        registration_info = json.loads(request.body)
        JiraAuth.objects.create(
            client_key=registration_info['clientKey'],
            shared_secret=registration_info['sharedSecret'],
            base_url=registration_info['baseUrl'],
            public_key=registration_info['publicKey']
        )
        return HttpResponse(json.dumps({}), content_type='application/json')
