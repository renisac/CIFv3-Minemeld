from __future__ import absolute_import

import logging
import requests
from minemeld.ft.basepoller import BasePollerFT
from cifv3 import __version__
from time import sleep
import json
from base64 import b64decode
import yaml
import os

LOG = logging.getLogger(__name__)

ITYPE_MAP = {
    'email': 'email-addr',
    'ipv4': 'IPv4',
    'ipv6': 'IPv6',
    'fqdn': 'domain',
    'url': 'URL'
}

class Miner(BasePollerFT):

    def configure(self):
        super(Miner, self).configure()

        self.verify_cert = self.config.get('verify_cert', True)
        self.initial_days = self.config.get('initial_days', 7)
        self.prefix = self.config.get('prefix', 'cifv3')
        self.remote = self.config.get('remote', None)
        self.token = self.config.get('token', None)
        self.filters = self.config.get('filters', None)
        self.fields = ['tlp', 'group', 'reporttime', 'indicator', 'firsttime', 'lasttime', 'count', 'tags',
                       'description', 'confidence', 'rdata', 'provider']
        
        self.api_endpoint = '/feed'

        self.side_config_path = os.path.join(
            os.environ['MM_CONFIG_DIR'],
            '{}_side_config.yml'.format(self.name)
        )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('{} - Error loading side config: {}'.format(self.name, str(e)))
            return

        self.token = sconfig.get('token', self.token)
        if self.token is not None:
            LOG.info('{} - token set'.format(self.name))

        self.remote = sconfig.get('remote', self.remote)
        self.verify_cert = sconfig.get('verify_cert', self.verify_cert)
        filters = sconfig.get('filters', self.filters)
        if filters is not None:
            if self.filters is not None:
                self.filters.update(filters)
            else:
                self.filters = filters

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Miner, self).hup(source=source)
                
    def _check_status(self, resp, expect=200):
        if resp.status_code == 400:
            r = json.loads(resp.text)
            raise RuntimeError(r['message'])

        if resp.status_code == 401:
            raise RuntimeError('unauthorized. check token?')

        if resp.status_code == 404:
            raise RuntimeError('not found. check remote api url?')

        if resp.status_code == 408:
            raise RuntimeError('timeout')

        if resp.status_code == 422:
            msg = json.loads(resp.text)
            raise RuntimeError(msg['message'])

        if resp.status_code == 429:
            raise RuntimeError('RateLimit exceeded')

        if resp.status_code in [500, 501, 502, 503, 504]:
            raise RuntimeError('system seems busy..')

        if resp.status_code != expect:
            msg = 'unknown: %s' % resp.content
            raise RuntimeError(msg)

    def _process_item(self, item):

        indicator = item.get('indicator', None)
        if indicator is None:
            LOG.error('{} - no indicator in item'.format(self.name))
            return [[None, None]]

        itype = item.get('itype', None)
        if itype is None:
            LOG.error('{} - no itype in item'.format(self.name))
            return [[None, None]]

        # translate itype
        if itype in ['email', 'ipv4', 'ipv6', 'fqdn', 'url']:
            itype = ITYPE_MAP[itype]
        elif itype in ['md5', 'sha1', 'sha256', 'ssdeep']:
            # no mapping needed for these
            pass
        else:
            LOG.error('{} - unahndled itype {}'.format(self.name, itype))
            return [[None, None]]

        # build attributes to return
        a = {}

        # minemeld attrib is just called 'type'
        a['type'] = itype

        for field in self.fields:
            if field in ['indicator', 'itype', 'confidence']:
                continue

            if field not in item:
                continue

            a['{}_{}'.format(self.prefix, field)] = item[field]

        if item.get('confidence'):
            # minemeld confidence scores are 0-100, so multiply CIF conf by 10 to equivocate
            a['confidence'] = (item['confidence'] * 10)

        LOG.debug('{} - {}: {}'.format(self.name, indicator, a))

        return [[indicator, a]]

    def _build_iterator(self, now):

        if self.remote is None:
            raise RuntimeError('{} - remote api is required'.format(self.name))

        if self.token is None:
            raise RuntimeError('{} - token is required'.format(self.name))

        if self.filters is None:
            raise RuntimeError('{} - feed filters are required'.format(self.name))
            
        if self.filters.get('itype') is None:
            raise RuntimeError('{} - itype in feed filters has not been set'.format(self.name))

        if self.filters.get('confidence') is None:
            raise RuntimeError('{} - confidence in feed filters has not been set'.format(self.name))

        if self.filters.get('tags') is None:
            raise RuntimeError('{} - tags in feed filters has not been set'.format(self.name))
        elif isinstance(self.filters['tags'], list):
            if 'whitelist' in self.filters['tags']:
                # /feed api endpoint doesn't allow whitelist tag due to server-side allowlisting logic
                self.api_endpoint = '/search'
                self.filters['limit'] = 50000
                # allowlists should be their own feed if being pulled through minemeld
                if len(self.filters['tags']) > 1:
                    raise RuntimeError('{} - feeds configured with "whitelist" tag cannot contain other tags'.format(self.name))
            # for later param parsing by 'requests' library, list of tags needs to form a url
            # such as /feed?tags=phishing,botnet as CIF server won't handle /feed?tags=phishing&tags=botnet
            self.filters['tags'] = ','.join(map(str, self.filters['tags']))

        LOG.debug('{} - filters: {}'.format(self.name, self.filters))

        ##
        # We are essentially replicating cifsdk behavior below to avoid cifsdk version clash on the box.
        # git submodule and venv is not an option for UI-based install.
        ##

        self.session = requests.Session()
        self.session.headers["Accept"] = 'application/vnd.cif.v3+json'
        self.session.headers['User-Agent'] = 'minemeld-cifv3/{}'.format(__version__)
        self.session.headers['Authorization'] = 'Token token=' + self.token
        self.session.headers['Content-Type'] = 'application/json'
        self.session.headers['Accept-Encoding'] = 'deflate'

        resp = self.session.get('{}{}'.format(self.remote, self.api_endpoint), params=self.filters, verify=self.verify_cert
, timeout=120)

        try:
            self._check_status(resp, expect=200)
        except Exception as e:
            LOG.error('{} - cif feed error: {}'.format(self.name, e))
            raise

        data = resp.content

        s = (int(resp.headers['Content-Length']) / 1024 / 1024)

        msgs = json.loads(data.decode('utf-8'))

        if msgs.get('data') and msgs['data'] == '{}':
            msgs['data'] = []

        if msgs.get('data') and isinstance(msgs['data'], basestring) and msgs['data'].startswith(
                '{"hits":{"hits":[{"_source":'):
            msgs['data'] = json.loads(msgs['data'])
            msgs['data'] = [r['_source'] for r in msgs['data']['hits']['hits']]

        if not msgs.get('status') and not msgs.get('message') == 'success':
            LOG.error('{} - cif feed error: {}'.format(self.name, msgs))
            raise

        if msgs.get('status') and msgs['status'] == 'failed':
            LOG.error('{} - cif invalid search: {}'.format(self.name, msgs['message']))
            raise

        if isinstance(msgs.get('data'), list):
            LOG.info('{} - Received {} results from cif api'.format(self.name, len(msgs.get('data'))))
            for m in msgs['data']:
                if m.get('message'):
                    try:
                        m['message'] = b64decode(m['message'])
                    except Exception as e:
                        pass
        return msgs['data']
