from z3 import *

x = Real('x')
y = Real('y')
s = Solver()
s.add(x + y < 1, x > 1, y > 1)
print(s.check()) # >>> sat, unsat
print(s.model()) # >>> 구체적인 값 찾기
