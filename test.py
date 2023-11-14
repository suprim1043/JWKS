import unittest
from flask import Flask, jsonify
from jwks import app, private_key, jwks_entry, users



class TestJWKSApp(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True


    def test_jwks_endpoint(self):
        response = self.app.get('/.well-known/jwks.json')
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)
        
    #checks authentication with correct keys

    def test_authentication_endpoint(self):
        response = self.app.post('/auth', json={"username": "userABC", "password": "password123"})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', data)
    
    #checks authentication with wrong info
    def test_authentication_endpoint_wrong_info(self):
        response = self.app.post('/auth', json={"username": "useBC", "password": "passd123"})
        data = response.get_json()
        self.assertEqual(response.status_code, 401)

    #checks expired

    def test_authentication_expired_endpoint(self):
        response = self.app.post('/auth/expired', json={"username": "userABC", "password": "password123"})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', data)

   

if __name__ == '__main__':
    unittest.main()
