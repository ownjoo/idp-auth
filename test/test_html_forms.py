"""Form classification and submission semantics the generic flow relies on."""

import unittest

from idp_auth.html import Page

URL = 'https://idp.example.com/login'

SEARCH_THEN_LOGIN = """
<form action="/search"><input type="search" name="q"><button>Search</button></form>
<form action="/lang"><select name="lang"><option value="en">en</option></select><button>Go</button></form>
<form id="login" method="post" action="/auth">
  <input type="text" name="j_username"><input type="password" name="j_password">
  <button type="submit" name="_eventId_proceed">Login</button>
</form>
"""

OTP_FORM = """
<form method="post" action="/mfa">
  <input type="hidden" name="ctx" value="c1">
  <input type="text" name="VerificationCode" autocomplete="one-time-code">
  <input type="submit" name="SignIn" value="Verify">
</form>
"""

CONSENT = """
<form method="post" action="/consent">
  <input type="hidden" name="csrf" value="x">
  <input type="checkbox" name="remember" value="1" checked>
  <button type="submit" name="_eventId_proceed" value="accept">Accept</button>
  <button type="submit" name="_eventId_cancel">Reject</button>
</form>
"""


class TestKinds(unittest.TestCase):
    def test_kinds(self):
        forms = Page(SEARCH_THEN_LOGIN, URL).forms()
        self.assertEqual([f.kind for f in forms], ['other', 'other', 'credentials'])
        self.assertEqual(Page(OTP_FORM, URL).forms()[0].kind, 'otp')
        self.assertEqual(Page(CONSENT, URL).forms()[0].kind, 'interstitial')

    def test_username_only_is_credentials(self):
        page = Page('<form><input type="email" name="whatever"><button>Next</button></form>', URL)
        self.assertEqual(page.forms()[0].kind, 'credentials')

    def test_hidden_only_without_button_is_not_interstitial(self):
        self.assertEqual(Page('<form><input type="hidden" name="a" value="1"></form>', URL).forms()[0].kind, 'other')


class TestLoginFormSelection(unittest.TestCase):
    def test_skips_search_and_language_forms(self):
        form = Page(SEARCH_THEN_LOGIN, URL).login_form()
        self.assertEqual(form.action, 'https://idp.example.com/auth')

    def test_prefers_credentials_over_interstitial(self):
        form = Page(CONSENT + SEARCH_THEN_LOGIN, URL).login_form()
        self.assertEqual(form.kind, 'credentials')

    def test_otp_and_interstitial_found(self):
        self.assertEqual(Page(OTP_FORM, URL).login_form().kind, 'otp')
        self.assertEqual(Page(CONSENT, URL).login_form().kind, 'interstitial')

    def test_none_when_nothing_actionable(self):
        self.assertIsNone(Page('<form action="/search"><input type="search" name="q"></form>', URL).login_form())


class TestSubmitter(unittest.TestCase):
    def test_default_button_sent_on_submit(self):
        nav = Page(SEARCH_THEN_LOGIN, URL).login_form().to_navigation(submitter=True)
        self.assertEqual(nav.data['_eventId_proceed'], '')

    def test_first_submit_button_wins(self):
        nav = Page(CONSENT, URL).login_form().to_navigation(submitter=True)
        self.assertEqual(nav.data['_eventId_proceed'], 'accept')
        self.assertNotIn('_eventId_cancel', nav.data)

    def test_input_submit(self):
        nav = Page(OTP_FORM, URL).login_form().to_navigation(submitter=True)
        self.assertEqual(nav.data['SignIn'], 'Verify')

    def test_type_button_is_not_a_submitter(self):
        page = Page('<form><button type="button" name="b" value="1">x</button><input name="a"></form>', URL)
        self.assertNotIn('b', page.forms()[0].to_navigation(submitter=True).data)

    def test_script_submit_excludes_submitter(self):
        # form.submit() from script never includes a button, so auto-navigation must not either
        page = Page('<body onload="document.forms[0].submit()">' + CONSENT.replace('checkbox', 'hidden'), URL)
        self.assertNotIn('_eventId_proceed', page.auto_navigation().data)

    def test_fields_never_contain_buttons(self):
        self.assertNotIn('_eventId_proceed', Page(CONSENT, URL).forms()[0].fields)


class TestOtp(unittest.TestCase):
    def test_fill_otp_by_autocomplete(self):
        form = Page(OTP_FORM, URL).login_form()
        self.assertTrue(form.fill_otp('123456'))
        self.assertEqual(form.fields['VerificationCode'], '123456')

    def test_fill_otp_by_name(self):
        for name in ('otp', 'totp', 'code', 'passcode', 'otpCode', 'mfa_code'):
            form = Page(f'<form><input type="tel" name="{name}"><button>Go</button></form>', URL).forms()[0]
            self.assertEqual(form.kind, 'otp', name)
            self.assertTrue(form.fill_otp('1'), name)

    def test_no_otp_field(self):
        self.assertFalse(Page(SEARCH_THEN_LOGIN, URL).login_form().fill_otp('1'))

    def test_username_never_lands_in_otp_field(self):
        form = Page(OTP_FORM, URL).login_form()
        form.fill_credentials(username='svc', password='pw')
        self.assertEqual(form.fields['VerificationCode'], '')


class TestErrorText(unittest.TestCase):
    def test_common_error_containers(self):
        for markup in (
            '<p class="output--error">The password you entered was incorrect.</p>',
            '<div role="alert">The password you entered was incorrect.</div>',
            '<span id="errorText">The password you entered was incorrect.</span>',
            '<div class="alert alert-danger">The password you entered was incorrect.</div>',
            '<span class="kc-feedback-text">The password you entered was incorrect.</span>',
        ):
            self.assertEqual(Page(markup, URL).error_text(), 'The password you entered was incorrect.', markup)

    def test_empty_containers_ignored(self):
        self.assertIsNone(Page('<div role="alert"> </div><p>fine</p>', URL).error_text())

    def test_long_text_truncated(self):
        self.assertLessEqual(len(Page(f'<div class="error">{"x" * 1000}</div>', URL).error_text()), 200)


if __name__ == '__main__':
    unittest.main()
