# Copyright 2009 Max Klymyshyn, Sonettic
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __init__ import *
from apnsexceptions import *
import base64
import binascii
from connection import *
import logging
import select
from socket import error as socket_error
import struct
import threading
import time
from utils import _doublequote

NULL = 'null'

RESPONSE_NO_ERRORS_ENCOUNTERED = 0
RESPONSE_PROCESSING_ERROR = 1
RESPONSE_MISSING_DEVICE_TOKEN = 2
RESPONSE_MISSING_TOPIC = 3
RESPONSE_MISSING_PAYLOAD = 4
RESPONSE_INVALID_TOKEN_SIZE = 5
RESPONSE_INVALID_TOPIC_SIZE = 6
RESPONSE_INVALID_PAYLOAD_SIZE = 7
RESPONSE_INVALID_TOKEN = 8
RESPONSE_SHUTDOWN = 10
RESPONSE_UNKNOWN = 255

WAIT_READ_TIMEOUT_SEC = 10
ERROR_RESPONSE_LENGTH = 6
ERROR_RESPONSE_FORMAT = (
    '!'   # network big-endian
    'B'   # command
    'B'   # status
    'I'   # identifier
)

_logger = logging.getLogger(__name__)

class APNSAlert(object):
    """
    This is an object to generate properly APNS alert object with
    all possible values.
    """
    def __init__(self):
        self.alertBody = None
        self.actionLocKey = None
        self.locKey = None
        self.locArgs = None

    def body(self, alertBody):
        """
        The text of the alert message.
        """
        if alertBody and not isinstance(alertBody, str):
            raise APNSValueError, "Unexpected value of argument. It should be string or None."

        self.alertBody = alertBody
        return self

    def action_loc_key(self, alk = NULL):
        """
        If a string is specified, displays an alert with two buttons.
        """
        if alk and not isinstance(alk, str):
            raise APNSValueError, "Unexpected value of argument. It should be string or None."

        self.actionLocKey = alk
        return self

    def loc_key(self, lk):
        """
        A key to an alert-message string in a Localizable.strings file for the current
        localization (which is set by the user's language preference).
        """
        if lk and not isinstance(lk, str):
            raise APNSValueError, "Unexcpected value of argument. It should be string or None"
        self.locKey = lk
        return self

    def loc_args(self, la):
        """
        Variable string values to appear in place of the format specifiers in loc-key.
        """

        if la and not isinstance(la, (list, tuple)):
            raise APNSValueError, "Unexpected type of argument. It should be list or tuple of strings"

        self.locArgs = [ '"%s"' % str(x) for x in la ]
        return self

    def _build(self):
        """
        Build object to JSON Apple Push Notification Service string.
        """

        arguments = []
        if self.alertBody:
            arguments.append('"body":"%s"' % _doublequote(self.alertBody))

        if self.actionLocKey:
            arguments.append('"action-loc-key":"%s"' % _doublequote(self.actionLocKey))

        if self.locKey:
            arguments.append('"loc-key":"%s"' % _doublequote(self.locKey))

        if self.locArgs:
            arguments.append('"loc-args":[%s]' % ",".join(self.locArgs))

        return ",".join(arguments)

class APNSProperty(object):
    """
    This class should describe APNS arguments.
    """
    name = None
    data = None
    def __init__(self, name = None, data = None):
        if not name or not isinstance(name, str) or len(name) == 0:
            raise APNSValueError, "Name of property argument should be a non-empry string"

        if not isinstance(data, (int, str, list, tuple, float)):
            raise APNSValueError, "Data argument should be string, number, list of tuple"

        self.name = name
        self.data = data


    def _build(self):
        arguments = []
        name = '"%s":' % self.name

        if isinstance(self.data, (int, float)):
            return "%s%s" % (name, str(self.data))

        if isinstance(self.data, str) or isinstance(self.data, unicode):
            return '%s"%s"' % (name, _doublequote(self.data))

        if isinstance(self.data, (tuple, list)):
            arguments = map(lambda x: if_else(isinstance(x, str), '"%s"' % _doublequote(str(x)), str(x)), self.data)
            return "%s[%s]" % (name, ",".join(arguments))

        return '%s%s' % (name, NULL)

class APNSNotificationWrapper(object):
    """
    This object wrap a list of APNS tuples. You should use
    .append method to add notifications to the list. By usint
    method .notify() all notification will send to the APNS server.
    """
    sandbox = True
    apnsHost = 'gateway.push.apple.com'
    apnsSandboxHost = 'gateway.sandbox.push.apple.com'
    apnsPort = 2195
    payloads = None
    connection = None
    debug_ssl = False

    def __init__(self, certificate = None, sandbox = True, debug_ssl = False, \
                    force_ssl_command = False):
        self.debug_ssl = debug_ssl
        self.force_ssl_command = False
        self.connection = APNSConnection(certificate = certificate, \
                            force_ssl_command = self.force_ssl_command, debug = self.debug_ssl)
        self.sandbox = sandbox
        self.payloads = []


    def append(self, payload = None):
        """Append payload to wrapper"""
        if not isinstance(payload, APNSNotification):
            raise APNSTypeError, "Unexpected argument type. Argument should be an instance of APNSNotification object"
        self.payloads.append(payload)


    def count(self):
        """Get count of payloads
        """
        return len(self.payloads)

    def notify(self):
        """
        Send nofification to APNS:
            1) prepare all internal variables to APNS Payout JSON
            2) make connection to APNS server and send notification
        """
        payloads = [o.payload() for o in self.payloads]
        payloadsLen = sum([len(p) for p in payloads])
        messages = []
        offset = 0

        if len(payloads) == 0:
            return False

        for p in payloads:
            plen = len(p)
            messages.append(struct.pack('%ds' % plen, p))
            offset += plen

        # TODO: make it more correctly
        message = "".join(messages)

        apnsConnection = self.connection

        if self.sandbox != True:
            apnsHost = self.apnsHost
        else:
            apnsHost = self.apnsSandboxHost

        apnsConnection.connect(apnsHost, self.apnsPort)

        apnsConnection.write(message)

        rlist, _, _ = select.select([apnsConnection.context().connectionContext], [], [], WAIT_READ_TIMEOUT_SEC)
        error = None
        if len(rlist) > 0:
            data = self.apnsConnection.read(blockSize=ERROR_RESPONSE_LENGTH)
            if len(data) == ERROR_RESPONSE_LENGTH:
                command, status, identifier = struct.unpack(ERROR_RESPONSE_FORMAT, data)
                if command == 8:
                    error = (status, identifier)
                    _logger.info("got error response from APNs:" + str(error))
                    # TODO: resend

            if len(data) == 0:
                _logger.warning("read socket got 0 bytes data")

        apnsConnection.close()

        return True

class APNSNotification(object):
    """
    APNSNotificationWrapper wrap Apple Push Notification Service into
    python object.
    """

    command = 0
    badge = None
    sound = None
    alert = None

    deviceToken = None

    maxPayloadLength = 2048
    deviceTokenLength = 32

    properties = None

    def __init__(self):
        """
        Initialization of the APNSNotificationWrapper object.
        """
        self.properties = []
        self.badgeValue = None
        self.soundValue = None
        self.alertObject = None
        self.deviceToken = None


    def token(self, token):
        """
        Add deviceToken in binary format.
        """
        self.deviceToken = token
        return self

    def tokenBase64(self, encodedToken):
        """
        Add deviceToken as base64 encoded string (not binary)
        """
        self.deviceToken = base64.standard_b64decode(encodedToken)
        return self

    def tokenHex(self, hexToken):
        """
        Add deviceToken as a hexToken
        Strips out whitespace and <>
        """
        hexToken = hexToken.strip().strip('<>').replace(' ','').replace('-', '')
        self.deviceToken = binascii.unhexlify(hexToken)

        return self

    def unbadge(self):
        """Simple shorcut to remove badge from your application.
        """
        self.badge(0)
        return self

    def badge(self, num = None):
        """
        Add badge to the notification. If argument is None (by default it is None)
        badge will be disabled.
        """
        if num == None:
            self.badgeValue = None
            return self

        if not isinstance(num, int):
            raise APNSValueError, "Badge argument must be a number"
        self.badgeValue = num
        return self

    def sound(self, sound = 'default'):
        """
        Add a custom sound to the noficitaion. By defailt it is default sound ('default')
        """
        if sound == None:
            self.soundValue = None
            return self
        self.soundValue = str(sound)
        return self

    def alert(self, alert = None):
        """
        Add an alert to the Wrapper. It should be string or APNSAlert object instance.
        """
        if not isinstance(alert, str) and not isinstance(alert, unicode) and not isinstance(alert, APNSAlert):
            raise APNSTypeError, "Wrong type of alert argument. Argument should be String, Unicode string or an instance of APNSAlert object"
        self.alertObject = alert
        return self

    def appendProperty(self, *args):
        """
        Add a custom property to list of properties.
        """
        for prop in args:
            if not isinstance(prop, APNSProperty):
                raise APNSTypeError, "Wrong type of argument. Argument should be an instance of APNSProperty object"
            self.properties.append(prop)
        return self

    def clearProperties(self):
        """
        Clear list of properties.
        """
        self.properties = None

    def _build(self):
        """
        Build all notifications items to one string.
        """
        keys = []
        apsKeys = []
        if self.soundValue:
            apsKeys.append('"sound":"%s"' % _doublequote(self.soundValue))

        if self.badgeValue:
            apsKeys.append('"badge":%d' % int(self.badgeValue))

        if self.alertObject != None:
            alertArgument = ""
            if isinstance(self.alertObject, str):
                alertArgument = _doublequote(self.alertObject)
                apsKeys.append('"alert":"%s"' % alertArgument)
            elif isinstance(self.alertObject, APNSAlert):
                alertArgument = self.alertObject._build()
                apsKeys.append('"alert":{%s}' % alertArgument)

        keys.append('"aps":{%s}' % ",".join(apsKeys))

        # prepare properties
        for property in self.properties:
            keys.append(property._build())

        payload = "{%s}" % ",".join(keys)

        if len(payload) > self.maxPayloadLength:
            raise APNSPayloadLengthError, "Length of Payload more than %d bytes." % self.maxPayloadLength

        return payload

    def payload(self):
        if self.deviceToken == None:
            raise APNSUndefinedDeviceToken, "You forget to set deviceToken in your notification."

        payload = self._build()
        payloadLength = len(payload)
        tokenLength = len(self.deviceToken)
        tokenFormat = "s" * tokenLength
        payloadFormat = "s" * payloadLength

        apnsPackFormat = "!BH" + str(tokenLength) + "sH" + str(payloadLength) + "s"

        # build notification message in binary format
        return struct.pack(apnsPackFormat,
                                    self.command,
                                    tokenLength,
                                    self.deviceToken,
                                    payloadLength,
                                    payload)
