import copy,unittest
from sanitize_sarif import sanitize, allowed_export_url, validate_export_urls
class PublicationGuardTests(unittest.TestCase):
    def setUp(self):
        self.data={'version':'2.1.0','runs':[{'automationDetails':{'id':'synthetic','description':{'text':'fixture-private-id'}},'tool':{'driver':{'rules':[{'id':'40012'}]}},'results':[{'ruleId':'40012','message':{'text':'Reflected input'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'search'}}}],'partialFingerprints':{'stable':'abc'}}]}]}
    def test_only_optional_description_removed(self):
        result=sanitize(self.data,'synthetic-credential',['fixture-private-id'])
        self.assertNotIn('description',result['runs'][0]['automationDetails'])
        self.assertEqual(result['runs'][0]['results'],self.data['runs'][0]['results'])
        self.assertEqual(result['runs'][0]['tool'],self.data['runs'][0]['tool'])
    def test_secret_in_description_blocks(self):
        self.data['runs'][0]['automationDetails']['description']['text']='synthetic-credential'
        with self.assertRaises(ValueError):sanitize(self.data,'synthetic-credential',[])
    def test_private_data_in_finding_blocks(self):
        self.data['runs'][0]['results'][0]['message']['text']='fixture-private-id'
        with self.assertRaises(ValueError):sanitize(self.data,'synthetic-credential',['fixture-private-id'])
    def test_email_blocks(self):
        self.data['runs'][0]['results'][0]['message']['text']='synthetic@example.test'
        with self.assertRaises(ValueError):sanitize(self.data,'synthetic-credential',[])
class ExportURLTests(unittest.TestCase):
    scan_id='11111111-1111-1111-1111-111111111111'
    def test_exact_intended_urls(self):
        urls=['https://stackhawk.com','https://www.stackhawk.com/',
              'https://docs.stackhawk.com/vulnerabilities/40012/',
              'https://vuln.stackhawk.com/40012',
              'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
              'https://json.schemastore.org/sarif-2.1.0',
              'https://app.stackhawk.com/scans/'+self.scan_id,
              'https://app.stackhawk.com/scans/'+self.scan_id+'/finding/40012',
              'http://127.0.0.1:8768/search?q=hello',
              'https://STACKHAWK.COM:443/']
        for url in urls:
            with self.subTest(url=url): self.assertTrue(allowed_export_url(url,self.scan_id))
    def test_deceptive_hostnames(self):
        for url in ['https://stackhawk.com.evil.test/', 'https://www.stackhawk.com.evil.test/',
                    'https://evilstackhawk.com/', 'https://docs.stackhawk.com.evil.test/',
                    'https://app.stackhawk.com.evil.test/scans/'+self.scan_id,
                    'http://127.0.0.1.evil.test:8768/search']:
            with self.subTest(url=url): self.assertFalse(allowed_export_url(url,self.scan_id))
    def test_userinfo_rejected_in_either_direction(self):
        for url in ['https://stackhawk.com@evil.test/', 'https://evil.test@stackhawk.com/',
                    'https://user:password@docs.stackhawk.com/',
                    'http://user@127.0.0.1:8768/search']:
            with self.subTest(url=url): self.assertFalse(allowed_export_url(url,self.scan_id))
    def test_wrong_scheme_ports_and_malformed_urls(self):
        for url in ['http://stackhawk.com/', 'https://stackhawk.com:8443/',
                    'http://127.0.0.1:87680/search', 'https://stackhawk.com:invalid/',
                    'https://stackhawk.com\\@evil.test/', 'https://stackhawk.com\n.evil.test/']:
            with self.subTest(url=url): self.assertFalse(allowed_export_url(url,self.scan_id))
    def test_scan_link_exact_identity(self):
        for suffix in ['-extra','/extra','/finding/40012/extra','/finding/not-a-rule','?redirect=elsewhere','#other']:
            self.assertFalse(allowed_export_url('https://app.stackhawk.com/scans/'+self.scan_id+suffix,self.scan_id))
    def test_markdown_links_and_code_spans(self):
        validate_export_urls({'text':'[finding](https://app.stackhawk.com/scans/'+self.scan_id+'/finding/40012) at `http://127.0.0.1:8768`'},self.scan_id)
    def test_nested_sarif_links_checked_without_mutation(self):
        data={'runs':[{'results':[{'message':{'text':'See https://docs.stackhawk.com/vulnerabilities/40012/'}}]}]}
        before=copy.deepcopy(data);validate_export_urls(data,self.scan_id);self.assertEqual(before,data)
        data['runs'][0]['results'][0]['message']['text']='See https://stackhawk.com.evil.test/'
        with self.assertRaises(ValueError):validate_export_urls(data,self.scan_id)
        data['runs'][0]['results'][0]['message']['text']='See https://stackhawk.com)@evil.test/'
        with self.assertRaises(ValueError):validate_export_urls(data,self.scan_id)
if __name__=='__main__':unittest.main()
