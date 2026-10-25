import copy,unittest
from sanitize_sarif import sanitize
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
if __name__=='__main__':unittest.main()
