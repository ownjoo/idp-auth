import unittest

from idp_auth.html import Page

LOGIN = """
<html><body>
<form id="login" method="post" action="/login?x=1">
  <input type="hidden" name="csrf" value="tok">
  <input type="email" name="identifier">
  <input type="password" name="pw">
  <input type="checkbox" name="remember" value="yes" checked>
  <input type="checkbox" name="unchecked_box" value="no-send" >
  <select name="lang"><option value="en">en</option><option value="fr" selected>fr</option></select>
  <textarea name="note">hi</textarea>
  <button type="submit" name="action" value="go">Go</button>
</form>
</body></html>
"""

SAML_POST = """
<html><body onload="document.forms[0].submit()">
<form method="POST" action="https://sp.example.com/acs">
  <input type="hidden" name="SAMLResponse" value="PHNhbWw+">
  <input type="hidden" name="RelayState" value="rs">
  <noscript><input type="submit" value="Continue"></noscript>
</form></body></html>
"""

ENTRA_CONFIG = """
<script type="text/javascript">//<![CDATA[
$Config={"urlPost":"/common/login","sFT":"flow{}token","sFTName":"flowToken","nested":{"a":[1,2,{"b":"}"}]}};
//]]></script>
"""


class TestForms(unittest.TestCase):
    def test_form_fields_like_a_browser(self):
        page = Page(LOGIN, 'https://idp.example.com/start')
        form = page.form()
        self.assertEqual(form.method, 'POST')
        self.assertEqual(form.action, 'https://idp.example.com/login?x=1')
        # unchecked checkboxes and buttons are not submitted; selected option and textarea are
        self.assertEqual(
            form.fields, {'csrf': 'tok', 'identifier': '', 'pw': '', 'remember': 'yes', 'lang': 'fr', 'note': 'hi'}
        )

    def test_form_by_selector(self):
        page = Page(LOGIN + '<form id="other" action="/o"></form>', 'https://idp.example.com/')
        self.assertEqual(page.form('#other').action, 'https://idp.example.com/o')
        self.assertIsNone(page.form('#nope'))

    def test_default_action_is_page_url_and_method_get(self):
        form = Page('<form><input name="a" value="1"></form>', 'https://x.example/p?q=1').form()
        self.assertEqual(form.action, 'https://x.example/p?q=1')
        self.assertEqual(form.method, 'GET')

    def test_fill_by_role(self):
        form = Page(LOGIN, 'https://idp.example.com/').form()
        form.fill_credentials(username='svc', password='s3cret')
        self.assertEqual(form.fields['identifier'], 'svc')
        self.assertEqual(form.fields['pw'], 's3cret')
        self.assertEqual(form.fields['csrf'], 'tok')

    def test_fill_by_known_names(self):
        form = Page(
            '<form><input name="loginfmt"><input name="passwd" type="password"></form>', 'https://x.example/'
        ).form()
        form.fill_credentials(username='u', password='p')
        self.assertEqual(form.fields, {'loginfmt': 'u', 'passwd': 'p'})


class TestNavigation(unittest.TestCase):
    def test_auto_submit_form(self):
        page = Page(SAML_POST, 'https://idp.example.com/sso')
        nav = page.auto_navigation()
        self.assertEqual(nav.method, 'POST')
        self.assertEqual(nav.url, 'https://sp.example.com/acs')
        self.assertEqual(nav.data, {'SAMLResponse': 'PHNhbWw+', 'RelayState': 'rs'})

    def test_hidden_only_saml_form_without_script(self):
        page = Page(SAML_POST.replace(' onload="document.forms[0].submit()"', ''), 'https://idp.example.com/')
        self.assertIsNotNone(page.auto_navigation())

    def test_login_form_is_not_auto_submitted(self):
        self.assertIsNone(Page(LOGIN, 'https://idp.example.com/').auto_navigation())

    def test_meta_refresh(self):
        page = Page('<meta http-equiv="Refresh" content="0; URL=\'/next\'">', 'https://a.example/x/y')
        nav = page.auto_navigation()
        self.assertEqual((nav.method, nav.url), ('GET', 'https://a.example/next'))

    def test_js_location(self):
        for script in (
            'window.location.href = "/js1";',
            "location.replace('/js1')",
            'top.location="/js1"',
            'document.location.assign("/js1");',
        ):
            nav = Page(f'<script>{script}</script>', 'https://a.example/').auto_navigation()
            self.assertEqual(nav.url, 'https://a.example/js1', script)

    def test_js_location_unescapes(self):
        nav = Page(
            r'<script>window.location = "https:\/\/b.example\/p?a=1&b=2";</script>', 'https://a/'
        ).auto_navigation()
        self.assertEqual(nav.url, 'https://b.example/p?a=1&b=2')


class TestJsObject(unittest.TestCase):
    def test_extracts_balanced_json(self):
        cfg = Page(ENTRA_CONFIG, 'https://login.example/').js_object('$Config')
        self.assertEqual(cfg['sFT'], 'flow{}token')
        self.assertEqual(cfg['nested']['a'][2]['b'], '}')

    def test_missing_returns_none(self):
        self.assertIsNone(Page('<p>nothing</p>', 'https://x/').js_object('$Config'))


if __name__ == '__main__':
    unittest.main()
