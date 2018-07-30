import logging
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta
from collections import deque

import adal  #pylint: disable=E0401
import gevent
import requests
import yaml
import ujson as json
from gevent.queue import Queue, Empty, Full
from netaddr import IPNetwork
from requests.exceptions import RequestException

from minemeld.ft import ft_states  #pylint: disable=E0401
from minemeld.ft.base import _counting  #pylint: disable=E0401
from minemeld.ft.actorbase import ActorBaseFT  #pylint: disable=E0401

LOG = logging.getLogger(__name__)
AUTHORITY_BASE_URL = 'https://login.microsoftonline.com'
AUTHORITY_URL = 'https://login.microsoftonline.com/{}'
RESOURCE = 'https://securitycenter.onmicrosoft.com/windowsatpservice'
ENDPOINT_URL = 'https://partnerstifrontend-eus-prd.trafficmanager.net/threatintel/info'


class AuthConfigException(RuntimeError):
    pass


class Output(ActorBaseFT):
    def __init__(self, name, chassis, config):
        self._queue = None

        super(Output, self).__init__(name, chassis, config)

        self._push_glet = None
        self._checkpoint_glet = None
        self.api_client_id = str(uuid.uuid4())
        self.sequence_number = 0

    def configure(self):
        super(Output, self).configure()

        self.queue_maxsize = int(self.config.get('queue_maxsize', 100000))
        if self.queue_maxsize == 0:
            self.queue_maxsize = None
        self._queue = Queue(maxsize=self.queue_maxsize)

        self.client_id = self.config.get('client_id', None)
        self.client_secret = self.config.get('client_secret', None)
        self.tenant_id = self.config.get('tenant_id', None)

        self.sender_id = self.config.get('sender_id', 'minemeld')

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        client_id = sconfig.get('client_id', None)
        if client_id is not None:
            self.client_id = client_id
            LOG.info('{} - client_id set'.format(self.name))

        client_secret = sconfig.get('client_secret', None)
        if client_secret is not None:
            self.client_secret = client_secret
            LOG.info('{} - client_secret set'.format(self.name))

        tenant_id = sconfig.get('tenant_id', None)
        if tenant_id is not None:
            self.tenant_id = tenant_id
            LOG.info('{} - tenant_id set'.format(self.name))

    def _saved_state_restore(self, saved_state):
        super(Output, self)._saved_state_restore(saved_state)

        self.api_client_id = saved_state.get('api_client_id', None)
        self.sequence_number = saved_state.get('sequence_number', None)

        LOG.info('{} - saved state: api_client_id: {} sequence_number: {}'.format(
            self.name,
            self.api_client_id,
            self.sequence_number
        ))

    def _saved_state_create(self):
        sstate = super(Output, self)._saved_state_create()

        sstate['api_client_id'] = self.api_client_id
        sstate['sequence_number'] = self.sequence_number

        return sstate

    def _saved_state_reset(self):
        super(Output, self)._saved_state_reset()

        self.api_client_id = str(uuid.uuid4())
        self.sequence_number = 0

    def connect(self, inputs, output):
        output = False
        super(Output, self).connect(inputs, output)

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def _get_auth_token(self):
        if self.client_id is None:
            LOG.error('{} - client_id not set'.format(self.name))
            raise AuthConfigException('{} - client_id not set'.format(self.name))
        if self.client_secret is None:
            LOG.error('{} - client_secret not set'.format(self.name))
            raise AuthConfigException('{} - client_secret not set'.format(self.name))
        if self.tenant_id is None:
            LOG.error('{} - tenant_id not set'.format(self.name))
            raise AuthConfigException('{} - tenant_id not set'.format(self.name))

        context = adal.AuthenticationContext(
            AUTHORITY_URL.format(self.tenant_id),
            validate_authority=self.tenant_id != 'adfs',
            api_version=None
        )

        token = context.acquire_token_with_client_credentials(
            RESOURCE,
            self.client_id,
            self.client_secret
        )

        if token is None or 'accessToken' not in token:
            LOG.error('{} - Invalid token or accessToken not available'.format(self.name))
            raise RuntimeError('{} - Invalid token or accessToken not available'.format(self.name))

        return token['accessToken']

    def _get_endpoint_orgid(self, token):
        # this should look like 
        # {
        # u'AadTenantId': u'bb19bb5c-0e8d-4a73-bd6b-d015b298ecd7',
        # u'ServiceUri': u'https://partnerstifrontend-eus-prd.trafficmanager.net/threatintel/indicators',
        # u'ServiceType': 1,
        # u'WdAtpOrgId': u'55c01df7-a1eb-4eae-ae3b-a9b423d07d72'
        # }
        result = requests.get(
            ENDPOINT_URL,
            headers={
                'Authorization': 'Bearer {}'.format(token),
                'Content-Type': 'application/json'
            }
        )
        result.raise_for_status()

        result = result.json()
        LOG.debug('{} - endpoints: {}'.format(self.name, result))

        if result.get('AadTenantId', None) != self.tenant_id:
            raise AuthConfigException('{} - Endpoint response AadTenantId differs from tenant_id: {}'.format(self.name, result))

        endpoint = result.get('ServiceUri', None)
        if endpoint is None:
            raise AuthConfigException('{} - Endpoint response missing ServiceUri field: {}'.format(self.name, result))

        org_id = result.get('WdAtpOrgId', None)
        if endpoint is None:
            raise AuthConfigException('{} - Endpoint response missing WdAtpOrgId field: {}'.format(self.name, result))

        return endpoint, org_id

    def _push_indicators(self, token, endpoint, org_id, indicators):
        message = {
            'Id': self.api_client_id,
            'SequenceNumber': self.sequence_number,
            'SenderId': self.sender_id,
            'Indicators': list(indicators),
            'WdAtpOrgId': org_id
        }

        LOG.debug(message)

        result = requests.post(
            endpoint,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(token)
            },
            json=message
        )

        LOG.debug(result.text)

        result.raise_for_status()

    def _push_loop(self):
        while True:
            msg = self._queue.get()

            artifacts = deque()
            artifacts.append(msg)

            try:
                while len(artifacts) < 511:
                    artifacts.append(self._queue.get_nowait())
            except Empty:
                pass

            while True:
                result = None

                try:
                    LOG.info('{} - Sending {}:{}'.format(self.name, self.api_client_id, self.sequence_number))
                    token = self._get_auth_token()
                    LOG.debug('{} - token: {}'.format(self.name, token))

                    endpoint, org_id = self._get_endpoint_orgid(token)
                    LOG.debug('{} - endpoint: {} WdAtpOrgId: {}'.format(self.name, endpoint, org_id))

                    self._push_indicators(
                        token=token,
                        endpoint=endpoint,
                        org_id=org_id,
                        indicators=artifacts
                    )

                    self.sequence_number += 1
                    self.statistics['indicator.tx'] += len(artifacts)
                    break

                except gevent.GreenletExit:
                    return

                except RequestException as e:
                    LOG.error('{} - error submitting indicators - {}'.format(self.name, str(e)))

                    if result is not None and result.status_code >= 400 and result.status_code < 500:
                        LOG.error('{}: error in request - {}'.format(self.name, result.text))
                        self.statistics['error.invalid_request'] += 1
                        break

                    self.statistics['error.submit'] += 1
                    gevent.sleep(60)

                except AuthConfigException as e:
                    LOG.exception('{} - Error submitting indicators - {}'.format(self.name, str(e)))
                    self.statistics['error.submit'] += 1
                    gevent.sleep(60.0)

                except Exception as e:
                    LOG.exception('{} - error submitting indicators - {}'.format(self.name, str(e)))
                    self.statistics['error.submit'] += 1
                    gevent.sleep(120.0)

            gevent.sleep(0.1)

    def _encode_indicator(self, indicator, value, expired=False):
        type_ = value['type']

        description = '{} indicator from {}'.format(
            type_,
            ', '.join(value['sources'])
        )
        external_id = '{}:{}'.format(type_, indicator)
        expiration = datetime.utcnow() + timedelta(days=365)
        if expired:
            expiration = datetime.fromtimestamp(0)
        expiration = expiration.isoformat()

        result = {
            'Description': description,
            'Confidence': value['confidence'],
            'ExternalId': external_id,
            'IndicatorExpirationDateTime': expiration
        }

        if type_ == 'URL':
            result['Url'] = indicator
        elif type_ == 'domain':
            result['DNSDomainName'] = indicator
        elif type_ == 'md5':
            result['FileMD5'] = indicator
        elif type_ == 'sha256':
            result['FileSha256'] = indicator
        else:
            self.statistics['error.unhandled_type'] += 1
            raise RuntimeError('{} - Unhandled {}'.format(self.name, type_))

        return result

    def _checkpoint_check(self, source=None, value=None):
        t0 = time.time()

        while ((time.time() - t0) < 30) and self._queue.qsize() != 0:
            gevent.sleep(0.5)
        self._push_glet.kill()

        LOG.info('{} - checkpoint with {} elements in the queue'.format(self.name, self._queue.qsize()))
        super(Output, self).checkpoint(source=source, value=value)

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        try:
            self._queue.put(
                self._encode_indicator(indicator, value, expired=False),
                block=True,
                timeout=0.001
            )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        if value is None:
            self.statistics['error.no_value'] += 1
            return

        try:
            self._queue.put(
                self._encode_indicator(indicator, value, expired=True),
                block=True,
                timeout=0.001
            )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('checkpoint.rx')
    def checkpoint(self, source=None, value=None):
        self.state = ft_states.CHECKPOINT
        self._checkpoint_glet = gevent.spawn(
            self._checkpoint_check,
            source,
            value
        )

    def length(self, source=None):
        return self._queue.qsize()

    def start(self):
        super(Output, self).start()

        self._push_glet = gevent.spawn(self._push_loop)

    def stop(self):
        super(Output, self).stop()

        if self._push_glet is not None:
            self._push_glet.kill()

        if self._checkpoint_glet is not None:
            self._checkpoint_glet.kill()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()

    @staticmethod
    def gc(name, config=None):
        ActorBaseFT.gc(name, config=config)
        shutil.rmtree(name, ignore_errors=True)
