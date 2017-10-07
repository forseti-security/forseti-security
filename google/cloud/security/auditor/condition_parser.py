import sys
import traceback
import logging
from pyparsing import *
ParserElement.enablePackrat()

# from https://gist.github.com/cynici/5865326

def EvalSignOp(s, l, t):
    """Evaluate expressions with a leading + or - sign"""
    sign, value = t[0]
    mult = {'+':1, '-':-1}[sign]
    res = mult * value
    logging.debug("SIGN: t=%s res=%s" % (t, res))
    return res

def operatorOperands(tokenlist):
    """Generator to extract operators and operands in pairs"""
    it = iter(tokenlist)
    while 1:
        try:
            o1 = next(it)
            o2 = next(it)
            yield ( o1, o2 )
        except StopIteration:
            break

def EvalMultOp(s, l, t):
    """Evaluate multiplication and division expressions"""
    prod = t[0][0]
    for op,val in operatorOperands(t[0][1:]):
        if op == '*':
            prod *= val
        if op == '/':
            prod /= val
        if op == '//':
            prod //= val
        if op == '%':
            prod %= val
    logging.debug("MULT: t=%s res=%s" % (t, prod))
    return prod

def EvalAddOp(s, l, t):
    """Evaluate addition and subtraction expressions"""
    sum = t[0][0]
    for op,val in operatorOperands(t[0][1:]):
        if op == '+':
            sum += val
        if op == '-':
            sum -= val
    logging.debug("ADD: t=%s res=%s" % (t, sum))
    return sum
    
def EvalComparisonOp(s, l, t):
    """Evaluate comparison expressions"""
    opMap = {
        "<" : lambda a,b : a < b,
        "<=" : lambda a,b : a <= b,
        ">" : lambda a,b : a > b,
        ">=" : lambda a,b : a >= b,
        "==" : lambda a,b : a == b,
        "!=" : lambda a,b : a != b,
        }
    res = False
    val1 = t[0][0]
    for op,val2 in operatorOperands(t[0][1:]):
        fn = opMap[op]
        if not fn(val1,val2):
            break
        val1 = val2
    else:
        res = True
    logging.debug("COMP: t=%s res=%s\n" % (t, res))
    return res

def EvalAnd(s, l, t):
    """Evaluate `and` expression."""
    bool1, op, bool2 = t[0]
    res = bool1 and bool2
    logging.debug("%s %s %s res=%s" % (bool1, op, bool2, res))
    return res

def EvalOr(s, l, t):
    """Evaluate `or` expression."""
    bool1, op, bool2 = t[0]
    res = bool1 or bool2
    logging.debug("%s %s %s res=%s" % (bool1, op, bool2, res))
    return res
    
def EvalNot(s, l, t):
    """Evaluate `not` expression."""
    op, bool1 = t[0]
    res = not bool1
    logging.debug("%s %s res=%s" % (op, bool1, res))
    return res

Param = Word(alphas+"_", alphanums+"_")
Qstring = quotedString(r".*").setParseAction(removeQuotes)
PosInt = Word(nums).setParseAction(lambda s,l,t: [int(t[0])])
PosReal = ( Combine(Word(nums) + Optional("." + Word(nums))
        + oneOf("E e") + Optional( oneOf('+ -')) + Word(nums))
        | Combine(Word(nums) + "." + Word(nums))
).setParseAction(lambda s,l,t: [float(t[0])])

signop = oneOf('+ -')
multop = oneOf('* / // %')
plusop = oneOf('+ -')
comparisonop = oneOf("< <= > >= == !=")

andop = CaselessKeyword("AND")
orop = CaselessKeyword("OR")
notop = CaselessKeyword("NOT")

class ConditionParser:
    """Parser class."""

    def __init__(self, param_dic={}):
        self.param_dic = {}
        # Save parameters (key-value pairs), but with capitalized key
        for k, v in param_dic.items():
            K = k.upper()
            if K in self.param_dic:
                raise ValueError("Parameter key collision: '%s'" % k)
            self.param_dic[K] = v

    def setParam(self, s, l, t):
        "Replace keywords with actual values using param_dic mapping"
        param = t[0].upper()
        return self.param_dic.get(param, '')

    def eval_filter(self, filter_expr):
        keyword = Param.copy()
        atom = PosReal | PosInt | Qstring | keyword.setParseAction(self.setParam)
        expr = operatorPrecedence(atom, [
            (signop, 1, opAssoc.RIGHT, EvalSignOp),
            (multop, 2, opAssoc.LEFT, EvalMultOp),
            (plusop, 2, opAssoc.LEFT, EvalAddOp),
            (comparisonop, 2, opAssoc.LEFT, EvalComparisonOp),
            (CaselessKeyword("NOT"), 1, opAssoc.RIGHT, EvalNot),
            (CaselessKeyword("AND"), 2, opAssoc.LEFT, EvalAnd),
            (CaselessKeyword("OR"), 2, opAssoc.LEFT, EvalOr),            
        ])
        return expr.parseString(filter_expr, parseAll=True)[0]


def parse(filter_expr, expected, params, parser=ConditionParser):
    if not parser:
        parser = ConditionParser(params)
    
    print 'expr: %s, expected: %s' % (filter_expr, expected)

    result = parser.eval_filter(filter_expr)
    if result != expected:
        raise AssertionError("yields %s" % (result))
    print 'Ok'

def main():
    parameters = {
        'FRP': 100,
        'satellite': 'A',    
    }
    tests = [
        # ( Filter_string, Expected_result )
        ( "199 / 2 > FRP", False ),
        ( "101 == FRP + 1", True ),
        ( "5 + 45 * 2 > FRP", False ),
        ( "-5+5 < FRP", True ),
        ( "satellite == 'N'", False),
        ( "1", True),
        ( "0", False),
        ( "FRP - 100 == 0", True),
        ( "FRP == 1 and satellite == 'T'", False ),
        ( "FRP != 1 and not satellite == 'T'", True ),
        # packrat speeds up nested expressions tremendously
        ( "(FRP == 1) and ((satellite == 'T') or (satellite == 'A'))", False ),
    ]
    
    logging.basicConfig(level=logging.WARNING)
    got_error = 0
    ap = ConditionParser(parameters)
    for filter_expr, expected in tests:
        try:
            parse(filter_expr, expected, parameters, ap)
        except Exception, err:
            traceback.print_exc(file=sys.stderr)
            print "%s: %s" % (filter_expr, err)
            got_error += 1
    return got_error
    
if __name__ == "__main__":
    sys.exit(main())
