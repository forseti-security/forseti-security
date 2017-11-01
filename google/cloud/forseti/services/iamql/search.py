from pyparsing import *
import unittest


class Node(list):
    def __eq__(self, other):
        return list.__eq__(self, other) and self.__class__ == other.__class__
        
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, list.__repr__(self))

    @classmethod
    def group(cls, expr):
        def group_action(s, l, t):
            try:
                lst = t[0].asList()
            except (IndexError, AttributeError), e:
                lst = t
            return [cls(lst)]

        return Group(expr).setParseAction(group_action)

    def get_query(self):
        raise NotImplementedError()


class TextNode(Node): pass
class ExactNode(Node): pass
class ComparisonNode(Node): pass


unicode_printables = u''.join(unichr(c) for c in xrange(65536)
                                        if not unichr(c).isspace())

word = TextNode.group(Word(unicode_printables))
exact = ExactNode.group(QuotedString('"', unquoteResults=True, escChar='\\'))
term = exact | word
comparison_name = Word(unicode_printables, excludeChars=':')
comparison = ComparisonNode.group(comparison_name + Literal(':') + term)
content = OneOrMore(comparison | term)


class ParserTestCase(unittest.TestCase):
    """ Tests the internals of the parser. """

    def assertMatch(self, parser, input):
        parser.parseString(input, parseAll=True)

    def assertNoMatch(self, parser, input):
        try:
            parser.parseString(input, parseAll=True)
        except ParseException:
            pass
        else:
            raise ValueError('match should fail', input)

    def test_word(self):
        self.assertMatch(word, 'john')
        self.assertNoMatch(word, 'john taylor')

    def test_exact(self):
        self.assertMatch(exact, '"john taylor"')
        self.assertMatch(exact, r'"John said \"Hello world\""')
        self.assertNoMatch(exact, 'john')

    def test_term(self):
        self.assertMatch(term, 'john')
        self.assertMatch(term, '"john taylor"')
        self.assertNoMatch(term, 'john taylor')

    def test_comparison(self):
        self.assertMatch(comparison, 'created_by: justin')
        self.assertMatch(comparison, 'created_by : justin')
        self.assertMatch(comparison, 'created_by :justin')
        self.assertMatch(comparison, 'location: "san francisco"')
        self.assertNoMatch(comparison, 'justin')

    def test_content(self):
        self.assertMatch(content, 'john')
        self.assertMatch(content, '"john taylor"')
        self.assertMatch(content, 'john taylor')
        self.assertMatch(content, 'calls: 0 status: trial')
        self.assertMatch(content, 'john calls: 0 status: "trial expired"')
        self.assertMatch(content, 'spam "john taylor" bacon egg')


class ASTTestCase(unittest.TestCase):
    """ Ensures the abstract syntax tree is generated properly. """

    def assertAstMatch(self, input, expected_ast):
        ast = content.parseString(input, parseAll=True).asList()
        self.assertEqual(ast, expected_ast)

    def test_parser(self):
        self.assertAstMatch('john "new york"', [
            TextNode(['john']),
            ExactNode(['new york']),
        ])

        self.assertAstMatch('email_opened: yes', [
            ComparisonNode(['email_opened', ':', TextNode(['yes'])]),
        ])

        self.assertAstMatch('location: "los angeles"', [
            ComparisonNode(['location', ':', ExactNode(['los angeles'])]),
        ])

        self.assertAstMatch('phone: 415 status: "trial expired" john', [
            ComparisonNode(['phone', ':', TextNode(['415'])]),
            ComparisonNode(['status', ':', ExactNode(['trial expired'])]),
            TextNode(['john']),
        ])


if __name__ == '__main__':
    unittest.main()
