# "THE BEER-WARE LICENSE" (Revision 42):
# <Filip.Palian@pjwstk.edu.pl> wrote this file.  As long as you retain
# this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.

from burp import IBurpExtender, IHttpListener, IScannerCheck
from burp import IScanIssue, ITab
from javax.swing import JPanel, JButton, JTextField
from java.net import URL
from array import array
from glob import glob
from re import match

NAME = 'AWS Security Checks'
VERSION = '0.2'
AUTHOR = 'Filip.Palian@pjwstk.edu.pl'

g_callbacks = None
g_helpers = None
g_secrets = ['S3_KEY', 'S3_SECRET', 'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY', 'AccessKeyId', 'SecretAccessKey',
    'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'
]
g_keyid = ''
g_key = ''
g_sdk = False

try:
    import boto3
    g_sdk = True
except ImportError:
    print 'Failed to load boto3 AWS SDK for Python! ' \
        + 'Some checks will be skipped without it. Install boto3 by ' \
        + 'running: pip install boto3 --target ~/path_to_your/bapp/' \
        + 'Lib\nIf you are on Mac OS and use homebrew check: ' \
        + 'https://stackoverflow.com/questions/135035/' \
        + 'python-library-path'

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck,
    IScanIssue, ITab):
    def registerExtenderCallbacks(self, callbacks):
        global g_callbacks, g_helpers, g_keyid, g_key

        g_helpers = callbacks.getHelpers()
        g_callbacks = callbacks
        callbacks.setExtensionName(NAME)
        callbacks.registerScannerCheck(S3_Bucket())
        callbacks.registerScannerCheck(S3_Secrets())

        keyid = callbacks.loadExtensionSetting('keyid')
        key = callbacks.loadExtensionSetting('key')

        if keyid and len(keyid) > 0:
            g_keyid = keyid
        if key and len(key) > 0:
            g_key = key

        self.customTab()

        print NAME + ' v' + VERSION \
            + ' plugin registered successfully.\n\n' \
            + 'Send feedback and bug reports to: ' + AUTHOR + '\n'

        print 'Passive checks performed:\n' \
            + '  - AWS secrets returned in response\n'

        print 'Active checks performed:\n' \
            + '  - S3 buckets in use\n' \
            + '  - S3 buckets unauth read\n' \
            + '  - S3 buckets unauth write\n' \
            + '  - S3 buckets authed read (requires AWS SDK)\n' \
            + '  - S3 buckets authed write (requires AWS SDK)\n' \
            + '  - AWS secrets accessible via meta-data\n'

        return 

    def customTab(self):
        self.panel = JPanel()

        if len(g_keyid) > 0:
            self.tf1 = JTextField(g_keyid, 15)
        else:
            self.tf1 = JTextField('AWS_ACCESS_KEY_ID', 15)

        if len(g_key) > 0:
            self.tf2 = JTextField(g_key, 15)
        else:
            self.tf2 = JTextField('AWS_SECRET_ACCESS_KEY', 15)

        self.btn = JButton('Save', actionPerformed = self.btn_onClick)

        self.panel.add(self.tf1)
        self.panel.add(self.tf2)
        self.panel.add(self.btn)

        g_callbacks.customizeUiComponent(self.panel)
        g_callbacks.addSuiteTab(self)

        return

    def btn_onClick(self, event):
        global g_keyid, g_key

        if self.tf1.text == '':
            g_keyid = 'AWS_ACCESS_KEY_ID'
        else:
            g_keyid = self.tf1.text

        if self.tf2.text == '':
            g_key = 'AWS_SECRET_ACCESS_KEY'
        else:
            g_key = self.tf2.text

        g_callbacks.saveExtensionSetting('keyid', g_keyid)
        g_callbacks.saveExtensionSetting('key', g_key)

        return

    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self.panel

# https://support.portswigger.net/customer/portal/questions/17039679
#   -saxparser-dependency-delimma
# http://www.jython.org/jythonbook/en/1.0/appendixB.html#working
#   -with-classpath
# http://python.6.x6.nabble.com/Jython-2-7a2-Issues-with-jarray-and-java
#   -lang-String-Console-prompt-goes-quot-off-quot-td5001336.html
class classPathHacker:
    import java.lang.reflect.Method
    import java.io.File
    from java.net import URL, URLClassLoader
    import jarray

    def addFile(self, s):
        f = self.java.io.File(s)
        u = f.toURL()
        a = self.addURL(u)
        return a

    def addURL(self, u):
        sysloader = self.java.lang.ClassLoader.getSystemClassLoader()
        sysclass = self.java.net.URLClassLoader
        method = sysclass.getDeclaredMethod("addURL", [self.java.net.URL])
        a = method.setAccessible(1)
        jar_a = self.jarray.array([u], self.java.lang.Object)
        b = method.invoke(sysloader, [u])
        return u

class S3_Bucket(IScannerCheck):
    writeRequestResponse = None
    getRequestResponse = None

    def doPassiveScan(self, baseRequestResponse):
        return []

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        name = 'AWS S3 bucket in use'
        detail = ''
        host = baseRequestResponse.getHttpService().getHost()
        s3host = host + '.s3.amazonaws.com'
        s3request = 'GET / HTTP/1.1\r\nHost: ' + s3host + '\r\n\r\n'
        region = 'unknown'
        issue = []

        # XXX: at the moment no need for SSL 
        httpService = g_helpers.buildHttpService(s3host, 80, False)

        checkRequestResponse = g_callbacks.makeHttpRequest(
            httpService, g_helpers.stringToBytes(s3request)
        )

        code = g_helpers.analyzeResponse(
            checkRequestResponse.getResponse()
        ).getStatusCode()

        headers = g_helpers.analyzeResponse(
            checkRequestResponse.getResponse()
        ).getHeaders()

        for header in headers:
            if 'x-amz-bucket-region: ' in header:
                region = header[21:]

        if code == 200 or code == 307:
            detail = 'Target allows unauthenticated read-only access to' \
                + ' AWS S3 bucket located at <b>' + s3host + '</b>. ' \
                + 'Manual verification is required to determine if ' \
                + 'anyone can also store data in this bucket. Region ' \
                + 'for this bucket is <b>' + region + '</b>.'

            issue = [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    URL('http://' + host + ':80'),
                    [checkRequestResponse],
                    name,
                    detail,
                    'Medium',
                    'Certain'
            )]

            if self.chkUnauthBucketWrite(httpService):
                detail = 'Target allows unauthenticated read-write ' \
                    + 'access to AWS S3 bucket located at <b>' \
                    + s3host + '</b>. Region for this bucket is <b>' \
                    + region \ + '</b>.'
  
                issue = [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.writeRequestResponse,
                            self.getRequestResponse],
                        name,
                        detail,
                        'High',
                        'Certain'
                )]
            elif self.chkAuthBucketWrite(httpService, region):
                detail = 'Target allows authenticated read-write access' \
                    + 'to AWS S3 bucket located at <b>' + s3host \
                    + '</b>. Region for this bucket is <b>' + region \
                    + '</b>.'
    
                issue = [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        URL('http://' + host + ':80'),
                        [baseRequestResponse],
                        name,
                        detail,
                        'High',
                        'Certain'
                )]
        elif code == 403:
            detail = 'Target uses AWS S3 bucket located at <b>' \
                + s3host + '</b> but public access is forbidden. In ' \
                + 'order to read or write data to this bucket one ' \
                + 'needs to know its AWS_ACCESS_KEY_ID and ' \
                + 'AWS_SECRET_ACCESS_KEY.'

            issue = [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    URL('http://' + host + ':80'),
                    [checkRequestResponse],
                    name,
                    detail,
                    'Information',
                    'Certain'
            )]

            if self.chkUnauthBucketWrite(httpService):
                detail = 'Target allows unauthenticated write-only ' \
                    + 'access to AWS S3 bucket located at <b>' \
                    + s3host + '</b>. Region for this bucket is <b>' \
                    + region \ + '</b>.'

                issue = [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        URL('http://' + host + ':80'),
                        [self.writeRequestResponse,
                            self.getRequestResponse],
                        name,
                        detail,
                        'High',
                        'Certain'
                )]
            elif self.chkAuthBucketWrite(httpService, region):
                detail = 'Target allows authenticated write-only access' \
                    + 'to AWS S3 bucket located at <b>' + s3host \
                    + '</b>. Region for this bucket is <b>' + region \
                    + '</b>.'

                issue = [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        URL('http://' + host + ':80'),
                        [baseRequestResponse],
                        name,
                        detail,
                        'High',
                        'Certain'
                )]

        return issue

    # Analogic check for DELETE can be easily added
    def chkUnauthBucketWrite(self, httpService):
        s3host = httpService.getHost()
        s3request = 'PUT /tekcub HTTP/1.1\r\nHost: ' + s3host + '\r\n' \
            + 'Content-Length: 6\r\n\r\ntekcub\r\n'

        self.writeRequestResponse = g_callbacks.makeHttpRequest(
            httpService, g_helpers.stringToBytes(s3request)
        )

        s3request = 'GET /tekcub HTTP/1.1\r\nHost: ' + s3host + '\r\n\r\n'

        self.getRequestResponse = g_callbacks.makeHttpRequest(
            httpService, g_helpers.stringToBytes(s3request)
        )

        code = g_helpers.analyzeResponse(
             self.getRequestResponse.getResponse()
        ).getStatusCode()

        if code == 200:
            return True

        return False
        
    def chkAuthBucketWrite(self, httpService, region):
        global g_sdk

        response = ''

        if g_sdk:
            try:
                client = boto3.client(
                    's3',
                    aws_access_key_id = g_keyid,
                    aws_secret_access_key = g_key,
                    # XXX: at the moment no need for SSL
                    endpoint_url = 'http://' + httpService.getHost(),
                    region_name = region
                )
                try:
                    response = client.list_buckets()
                except:
                    try: # hackety hack
                        for path in sys.path:
                            jythonPath = glob(path + '/jython*.jar')

                            if len(jythonPath) > 0:
                                classPathHacker().addFile(jythonPath[0])
                                break

                        response = client.list_buckets()
                    except Exception, e:
                        print 'Exception in chkBucketWrite(): ' + str(e)
                        print 'Failed to find and load required ' \
                            + 'modules. Set "Extender" > "Options" ' \
                            + '> "Python Environment" > "Folder for ' \
                            + 'loading modules (optional)" to point ' \
                            + 'on the same directory where the Jython ' \
                            + 'JAR archive is located.'
                        g_sdk = False
                        return False
            except Exception, e:
                print 'Exception in chkBucketWrite(): ' + str(e)
                g_sdk = False
                return False

            # TODO: handle different responses, e.g. invalid
            # region/secrets etc.
            if len(response) > 0:
                print response
                try:
                    client.create_bucket(Bucket='tekcub')
                except Exception, e:
                    print 'Exception in chkBucketWrite(): ' + str(e)
                    return False

                return True

        return False

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class S3_Secrets(IScannerCheck):
    def doPassiveScan(self, baseRequestResponse):
        name = 'AWS secrets found in response'
        host = g_helpers.analyzeRequest(baseRequestResponse).getUrl()
        detail = 'Secrets to AWS were found in response'
        matches = []

        response = baseRequestResponse.getResponse()

        for secret in g_secrets:
            matches += self.get_matches(
                response, bytearray(secret)
            )

        if (len(matches) > 0):
            return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    host,
                    [g_callbacks.applyMarkers(
                        baseRequestResponse, None, matches
                    )],
                    name,
                    detail,
                    'High',
                    'Tentative'
                )
            ]        
        return []

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        name = 'AWS secrets found in meta-data'
        host = g_helpers.analyzeRequest(baseRequestResponse).getUrl()
        detail = ''
        schemes = ['', 'http://', 'https://']
        httpService = baseRequestResponse.getHttpService()

        for scheme in schemes:
            payload = scheme + '169.254.169.254/latest/meta-data/' \
                + 'iam/security-credentials/'

            request = insertionPoint.buildRequest(payload)

            checkRequestResponse = g_callbacks.makeHttpRequest(
                httpService, request
            )

            code = g_helpers.analyzeResponse(
                checkRequestResponse.getResponse()
            ).getStatusCode()

            body_off = g_helpers.analyzeResponse(
                checkRequestResponse.getResponse()
            ).getBodyOffset()

            # FIXME: we need someting better than that
            if code == 200:
                body = g_helpers.bytesToString(
                    checkRequestResponse.getResponse()[body_off:]
                )
 
                m = match('^(\S+)$', body)

                if m:
                    payload += m.group(1)
                else:
                    continue

                request = insertionPoint.buildRequest(payload)

                checkRequestResponse = g_callbacks.makeHttpRequest(
                    httpService, request
                )

                response = checkRequestResponse.getResponse()

                matches = []
                for secret in g_secrets:
                    matches += self.get_matches(
                        response, bytearray(secret)
                    )

                if (len(matches) > 0):
                    detail = 'Target allows to access its instance ' \
                        + 'meta-data containing AWS secrets.'

                    return [CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            host,
                            [g_callbacks.applyMarkers(
                                checkRequestResponse, None, matches
                            )],
                            name,
                            detail,
                            'High',
                            'Certain'
                        )
                    ]
        return []

    def get_matches(self, response, match):
        matches = []
        start = 0
        rlen = len(response)
        mlen = len(match)

        while start < rlen:
            start = g_helpers.indexOf(response, match, True, start, rlen)
            if start == -1:
                break
            matches.append(array('i', [start, start + mlen]))
            start += mlen

        return matches

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail,
        severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService 
