"""Exercise HTTP parsing/guards without binding sockets."""
import io
import json
import unittest
from unittest.mock import patch
from server import Handler, ORIGIN

class RequestTests(unittest.TestCase):
    def request(self, path='/api/experiment', body=None, origin=ORIGIN, host='127.0.0.1:8765'):
        handler = object.__new__(Handler)
        raw = json.dumps(body if body is not None else {'count':1}).encode()
        handler.path = path
        handler.headers = {'Host':host, 'Origin':origin, 'Content-Length':str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        responses = []
        handler.send = lambda *args: responses.append(args)
        with patch('server.experiment', return_value={'ok':True}) as run:
            handler.do_POST()
            return responses[0], run.called

    def test_valid_request(self):
        response, called = self.request()
        self.assertEqual(response[0], 200)
        self.assertTrue(called)

    def test_cross_origin_rejected_before_work(self):
        response, called = self.request(origin='https://evil.invalid')
        self.assertEqual(response[0], 403)
        self.assertFalse(called)

    def test_rebinding_host_rejected(self):
        response, called = self.request(host='evil.invalid:8765')
        self.assertEqual(response[0], 403)
        self.assertFalse(called)

    def test_arbitrary_target_rejected(self):
        response, called = self.request(body={'target':'https://example.invalid'})
        self.assertEqual(response[0], 400)
        self.assertFalse(called)

    def test_oversized_body_rejected(self):
        response, called = self.request(body={'padding':'x'*600})
        self.assertEqual(response[0], 400)
        self.assertFalse(called)

    def test_unknown_route(self):
        response, called = self.request(path='/login')
        self.assertEqual(response[0],404)
        self.assertFalse(called)

if __name__ == '__main__': unittest.main()
