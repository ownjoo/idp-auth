import unittest

from idp_auth.template import lookup, render


class TestLookup(unittest.TestCase):
    def test_dotted_and_indexed(self):
        ctx = {'a': {'b': [{'c': 1}]}}
        self.assertEqual(lookup(ctx, 'a.b.0.c'), 1)

    def test_missing_is_none(self):
        self.assertIsNone(lookup({'a': {}}, 'a.b.c'))

    def test_dollar_in_key(self):
        self.assertEqual(lookup({'$Config': {'x': 1}}, '$Config.x'), 1)


class TestRender(unittest.TestCase):
    def test_whole_expression_keeps_type(self):
        self.assertEqual(render('${n}', {'n': 5}), 5)
        self.assertIsNone(render('${missing}', {}))

    def test_interpolation(self):
        self.assertEqual(render('Bearer ${t}', {'t': 'abc'}), 'Bearer abc')

    def test_interpolating_missing_is_empty(self):
        self.assertEqual(render('x=${missing}', {}), 'x=')

    def test_nested_structures_and_keys(self):
        ctx = {'k': 'flowToken', 'v': 'abc', 'none': None}
        out = render({'${k}': '${v}', 'static': ['${v}', 1], '${none}': 'dropped', 'gone': '${none}'}, ctx)
        self.assertEqual(out, {'flowToken': 'abc', 'static': ['abc', 1]})

    def test_non_strings_pass_through(self):
        self.assertEqual(render(3, {}), 3)
        self.assertTrue(render(True, {}))


if __name__ == '__main__':
    unittest.main()
